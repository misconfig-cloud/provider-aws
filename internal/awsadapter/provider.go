package awsadapter

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
	provideradapter "github.com/misconfig-cloud/provider-sdk"
)

const (
	Release             = "aws.sts-session@1.1.1"
	Provider            = "aws"
	CredentialKind      = "aws.process-credentials.v1"
	RevocationSemantics = "renewal-stops-immediately-existing-session-expires"
	MaximumTTL          = 15 * time.Minute
)

var roleARNPattern = regexp.MustCompile(`^arn:(aws|aws-us-gov|aws-cn):iam::([0-9]{12}):role/(.{1,512})$`)

type STSClient interface {
	AssumeRole(context.Context, *sts.AssumeRoleInput, ...func(*sts.Options)) (*sts.AssumeRoleOutput, error)
}

type Broker struct {
	Client             STSClient
	BrokerPrincipalARN string
	Now                func() time.Time
	NewExternalID      func() (string, error)
}

type connectionInput struct {
	RoleARN    string `json:"role_arn"`
	ExternalID string `json:"external_id,omitempty"`
}

type configuration struct {
	RoleARN    string `json:"role_arn"`
	ExternalID string `json:"external_id"`
}

type processCredentials struct {
	Version         int       `json:"Version"`
	AccessKeyID     string    `json:"AccessKeyId"`
	SecretAccessKey string    `json:"SecretAccessKey"`
	SessionToken    string    `json:"SessionToken"`
	Expiration      time.Time `json:"Expiration"`
}

func (b Broker) Prepare(_ context.Context, request provideradapter.PrepareRequest) (provideradapter.Connection, error) {
	if err := b.validateRequest(request.Provider, request.Release); err != nil {
		return provideradapter.Connection{}, err
	}
	var input connectionInput
	if json.Unmarshal(request.Input, &input) != nil {
		return provideradapter.Connection{}, errors.New("AWS connection input is invalid")
	}
	input.RoleARN, input.ExternalID = strings.TrimSpace(input.RoleARN), strings.TrimSpace(input.ExternalID)
	if !roleMatchesAccount(input.RoleARN, request.AccountRef) {
		return provideradapter.Connection{}, errors.New("AWS role does not match account_ref")
	}
	if input.ExternalID == "" {
		generator := b.NewExternalID
		if generator == nil {
			generator = randomExternalID
		}
		var err error
		input.ExternalID, err = generator()
		if err != nil {
			return provideradapter.Connection{}, err
		}
	}
	if len(input.ExternalID) < 16 || len(input.ExternalID) > 256 {
		return provideradapter.Connection{}, errors.New("AWS external ID must contain 16 to 256 characters")
	}
	configurationValue, _ := json.Marshal(configuration{RoleARN: input.RoleARN, ExternalID: input.ExternalID})
	onboarding, _ := json.Marshal(map[string]any{
		"kind": "aws_iam_role", "role_arn": input.RoleARN, "external_id": input.ExternalID,
		"broker_principal_arn": b.BrokerPrincipalARN,
		"trust_policy": map[string]any{
			"Version": "2012-10-17",
			"Statement": []map[string]any{
				{
					"Sid": "DenyWrongMisconfigExternalID", "Effect": "Deny",
					"Principal": map[string]string{"AWS": b.BrokerPrincipalARN}, "Action": "sts:AssumeRole",
					"Condition": map[string]any{
						"StringNotEquals": map[string]string{"sts:ExternalId": input.ExternalID},
					},
				},
				{
					"Sid": "AllowAttributedMisconfigSession", "Effect": "Allow",
					"Principal": map[string]string{"AWS": b.BrokerPrincipalARN}, "Action": []string{"sts:AssumeRole", "sts:SetSourceIdentity"},
					"Condition": map[string]any{
						"StringLike": map[string]string{"sts:SourceIdentity": "misconfig-*"},
					},
				},
			},
		},
		"permission_boundary": "Attach the documented read actions plus only the typed action permissions you intentionally enable. Every mutation is separately bound to one signed capability, exact resource, short-lived approval, execution receipt, and independent verification.",
	})
	return provideradapter.Connection{Configuration: configurationValue, Onboarding: onboarding}, nil
}

func (b Broker) Verify(ctx context.Context, request provideradapter.VerifyRequest) (provideradapter.Verification, error) {
	if err := b.validateRequest(request.Provider, request.Release); err != nil {
		return provideradapter.Verification{}, err
	}
	config, err := decodeConfiguration(request.Configuration, request.AccountRef)
	if err != nil {
		return provideradapter.Verification{}, err
	}
	identity := "misconfig-verify-" + shortHash(request.ConnectionID)
	output, err := b.assume(ctx, config, identity, identity, "")
	if err != nil {
		return provideradapter.Verification{}, err
	}
	if err := verifyAssumedIdentity(output.AssumedRoleUser, request.AccountRef); err != nil {
		return provideradapter.Verification{}, err
	}
	return provideradapter.Verification{TargetIdentity: config.RoleARN, VerifiedAt: b.now().UTC()}, nil
}

func (b Broker) Issue(ctx context.Context, request provideradapter.IssueRequest) (provideradapter.Material, error) {
	if err := b.validateRequest(request.Provider, request.Release); err != nil {
		return provideradapter.Material{}, err
	}
	config, err := decodeConfiguration(request.Configuration, request.AccountRef)
	if err != nil {
		return provideradapter.Material{}, err
	}
	digest, err := provideradapter.AuthorizationDigest(request.Authorization)
	if err != nil || digest != request.AuthorizationDigest || request.Subject.TenantID == "" ||
		request.Subject.SessionID == "" || request.Subject.AccountRef != request.AccountRef ||
		request.Authorization.Provider != Provider || request.Authorization.AccountRef != request.AccountRef ||
		len(request.Authorization.Environments) != 1 || request.Authorization.Environments[0] != request.Subject.Environment {
		return provideradapter.Material{}, errors.New("AWS credential lease identity or authorization changed")
	}
	policy, err := CompileSessionPolicy(request.Authorization, request.AccountRef)
	if err != nil {
		return provideradapter.Material{}, err
	}
	name := "misconfig-session-" + shortHash(request.Subject.SessionID)
	source := "misconfig-" + shortHash(strings.Join([]string{request.Subject.TenantID, request.Subject.ActorID, request.Subject.DeviceID, request.Subject.SessionID, request.Subject.ProfileID}, "\x00"))
	output, err := b.assume(ctx, config, name, source, policy)
	if err != nil {
		return provideradapter.Material{}, err
	}
	if err := verifyAssumedIdentity(output.AssumedRoleUser, request.AccountRef); err != nil {
		return provideradapter.Material{}, err
	}
	credentials := output.Credentials
	if credentials == nil || awssdk.ToString(credentials.AccessKeyId) == "" || awssdk.ToString(credentials.SecretAccessKey) == "" ||
		awssdk.ToString(credentials.SessionToken) == "" || credentials.Expiration == nil || !credentials.Expiration.After(b.now()) ||
		credentials.Expiration.After(b.now().Add(MaximumTTL).Add(time.Second)) {
		return provideradapter.Material{}, errors.New("AWS STS returned invalid credential material")
	}
	payload, _ := json.Marshal(processCredentials{Version: 1, AccessKeyID: awssdk.ToString(credentials.AccessKeyId), SecretAccessKey: awssdk.ToString(credentials.SecretAccessKey), SessionToken: awssdk.ToString(credentials.SessionToken), Expiration: credentials.Expiration.UTC()})
	return provideradapter.Material{Kind: CredentialKind, Payload: payload, ExpiresAt: credentials.Expiration.UTC(), TargetIdentity: config.RoleARN, RevocationSemantics: RevocationSemantics, AuthorizationDigest: digest}, nil
}

func (b Broker) validateRequest(provider, release string) error {
	if b.Client == nil || strings.TrimSpace(b.BrokerPrincipalARN) == "" || !strings.HasPrefix(b.BrokerPrincipalARN, "arn:") {
		return errors.New("AWS adapter is not configured")
	}
	if provider != Provider || release != Release {
		return errors.New("AWS provider release changed")
	}
	return nil
}

func (b Broker) assume(ctx context.Context, config configuration, name, sourceIdentity, policy string) (*sts.AssumeRoleOutput, error) {
	seconds := int32(MaximumTTL.Seconds())
	input := &sts.AssumeRoleInput{RoleArn: &config.RoleARN, RoleSessionName: &name, ExternalId: &config.ExternalID, DurationSeconds: &seconds, SourceIdentity: &sourceIdentity}
	if policy != "" {
		input.Policy = &policy
	}
	return b.Client.AssumeRole(ctx, input)
}

func (b Broker) now() time.Time {
	if b.Now != nil {
		return b.Now()
	}
	return time.Now()
}

func decodeConfiguration(encoded json.RawMessage, accountRef string) (configuration, error) {
	var config configuration
	if json.Unmarshal(encoded, &config) != nil || !roleMatchesAccount(strings.TrimSpace(config.RoleARN), accountRef) || len(strings.TrimSpace(config.ExternalID)) < 16 {
		return configuration{}, errors.New("AWS connection configuration is invalid")
	}
	return config, nil
}

func roleMatchesAccount(roleARN, accountRef string) bool {
	match := roleARNPattern.FindStringSubmatch(roleARN)
	return len(match) == 4 && match[2] == accountRef
}

func verifyAssumedIdentity(identity *ststypes.AssumedRoleUser, accountRef string) error {
	if identity == nil {
		return errors.New("AWS STS returned no assumed role identity")
	}
	arn := awssdk.ToString(identity.Arn)
	parts := strings.Split(arn, ":")
	if len(parts) < 6 || parts[2] != "sts" || parts[4] != accountRef || !strings.HasPrefix(parts[5], "assumed-role/") {
		return fmt.Errorf("AWS STS identity does not match account %s", accountRef)
	}
	return nil
}

func randomExternalID() (string, error) {
	value := make([]byte, 24)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return "misconfig-" + base64.RawURLEncoding.EncodeToString(value), nil
}

func shortHash(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:12])
}
