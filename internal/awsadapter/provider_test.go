package awsadapter

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
	provideradapter "github.com/misconfig-cloud/provider-sdk"
)

type fixtureSTS struct {
	inputs []*sts.AssumeRoleInput
	output *sts.AssumeRoleOutput
	err    error
}

func (f *fixtureSTS) AssumeRole(_ context.Context, input *sts.AssumeRoleInput, _ ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
	f.inputs = append(f.inputs, input)
	return f.output, f.err
}

func TestBrokerPreparesVerifiesAndIssuesExactScopedCredentials(t *testing.T) {
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	client := &fixtureSTS{output: assumed(now, "123456789012")}
	broker := Broker{Client: client, BrokerPrincipalARN: "arn:aws:iam::999999999999:role/MisconfigBroker", Now: func() time.Time { return now }, NewExternalID: func() (string, error) { return "misconfig-fixed-external-id", nil }}
	prepared, err := broker.Prepare(context.Background(), provideradapter.PrepareRequest{ConnectionID: "connection-1", TenantID: "tenant-1", Provider: Provider, Release: Release, AccountRef: "123456789012", Name: "Production", Input: json.RawMessage(`{"role_arn":"arn:aws:iam::123456789012:role/MisconfigSession"}`), Now: now})
	if err != nil {
		t.Fatal(err)
	}
	var onboarding map[string]any
	if json.Unmarshal(prepared.Onboarding, &onboarding) != nil || onboarding["broker_principal_arn"] == nil || onboarding["external_id"] == nil {
		t.Fatalf("onboarding instructions are incomplete: %s", prepared.Onboarding)
	}
	assertTrustPolicySeparatesExternalIDFromSourceIdentityPermission(t, prepared.Onboarding)
	verified, err := broker.Verify(context.Background(), provideradapter.VerifyRequest{RequestID: "verify-1", TenantID: "tenant-1", ConnectionID: "connection-1", Provider: Provider, Release: Release, AccountRef: "123456789012", Configuration: prepared.Configuration, Now: now})
	if err != nil || verified.TargetIdentity != "arn:aws:iam::123456789012:role/MisconfigSession" || len(client.inputs) != 1 || client.inputs[0].Policy != nil {
		t.Fatalf("verification changed: %#v %#v %v", verified, client.inputs, err)
	}
	authorization := fixtureAuthorization()
	digest, _ := provideradapter.AuthorizationDigest(authorization)
	material, err := broker.Issue(context.Background(), provideradapter.IssueRequest{RequestID: "lease-1", ConnectionID: "connection-1", Provider: Provider, Release: Release, AccountRef: "123456789012", Configuration: prepared.Configuration, Subject: provideradapter.Subject{TenantID: "tenant-1", ActorID: "actor-1", DeviceID: "device-1", SessionID: "session-1", ProfileID: "profile-1", AccountRef: "123456789012", Environment: "production"}, Authorization: authorization, AuthorizationDigest: digest, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if material.AuthorizationDigest != digest || material.Kind != CredentialKind || material.TargetIdentity != "arn:aws:iam::123456789012:role/MisconfigSession" || len(client.inputs) != 2 {
		t.Fatalf("issued material changed identity: %#v", material)
	}
	issued := client.inputs[1]
	if issued.Policy == nil || !strings.Contains(awssdk.ToString(issued.Policy), "ec2:DescribeInstances") || awssdk.ToString(issued.SourceIdentity) == "" || !strings.HasPrefix(awssdk.ToString(issued.SourceIdentity), "misconfig-") {
		t.Fatalf("STS issuance was not bounded and attributable: %#v", issued)
	}
	var payload map[string]any
	if json.Unmarshal(material.Payload, &payload) != nil || payload["Version"] != float64(1) || payload["AccessKeyId"] != "ASIAFIXTURE" {
		t.Fatalf("credential_process material is invalid: %s", material.Payload)
	}
}

func assertTrustPolicySeparatesExternalIDFromSourceIdentityPermission(t *testing.T, encoded json.RawMessage) {
	t.Helper()
	var onboarding struct {
		TrustPolicy struct {
			Statements []struct {
				Sid       string                       `json:"Sid"`
				Effect    string                       `json:"Effect"`
				Action    any                          `json:"Action"`
				Condition map[string]map[string]string `json:"Condition"`
			} `json:"Statement"`
		} `json:"trust_policy"`
	}
	if err := json.Unmarshal(encoded, &onboarding); err != nil {
		t.Fatal(err)
	}
	if len(onboarding.TrustPolicy.Statements) != 2 {
		t.Fatalf("trust policy statements=%d, want 2: %s", len(onboarding.TrustPolicy.Statements), encoded)
	}
	statements := map[string]struct {
		Effect    string
		Action    any
		Condition map[string]map[string]string
	}{}
	for _, statement := range onboarding.TrustPolicy.Statements {
		statements[statement.Sid] = struct {
			Effect    string
			Action    any
			Condition map[string]map[string]string
		}{statement.Effect, statement.Action, statement.Condition}
	}
	deny := statements["DenyWrongMisconfigExternalID"]
	if deny.Effect != "Deny" || deny.Action != "sts:AssumeRole" || deny.Condition["StringNotEquals"]["sts:ExternalId"] != "misconfig-fixed-external-id" {
		t.Fatalf("wrong external ID deny is incomplete: %#v", deny)
	}
	allow := statements["AllowAttributedMisconfigSession"]
	actions, ok := allow.Action.([]any)
	if !ok || allow.Effect != "Allow" || len(actions) != 2 || actions[0] != "sts:AssumeRole" || actions[1] != "sts:SetSourceIdentity" || allow.Condition["StringLike"]["sts:SourceIdentity"] != "misconfig-*" {
		t.Fatalf("source identity allow is incomplete: %#v", allow)
	}
	if _, exists := allow.Condition["StringEquals"]["sts:ExternalId"]; exists {
		t.Fatalf("source identity allow inherited the external ID: %#v", allow)
	}
}

func TestBrokerRejectsSubstitutionAndSTSAnomalies(t *testing.T) {
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	client := &fixtureSTS{output: assumed(now, "123456789012")}
	broker := Broker{Client: client, BrokerPrincipalARN: "arn:aws:iam::999999999999:role/MisconfigBroker", Now: func() time.Time { return now }}
	configuration := json.RawMessage(`{"role_arn":"arn:aws:iam::123456789012:role/MisconfigSession","external_id":"misconfig-fixed-external-id"}`)
	authorization := fixtureAuthorization()
	digest, _ := provideradapter.AuthorizationDigest(authorization)
	base := provideradapter.IssueRequest{RequestID: "lease", ConnectionID: "connection", Provider: Provider, Release: Release, AccountRef: "123456789012", Configuration: configuration, Subject: provideradapter.Subject{TenantID: "tenant", ActorID: "actor", DeviceID: "device", SessionID: "session", ProfileID: "profile", AccountRef: "123456789012", Environment: "production"}, Authorization: authorization, AuthorizationDigest: digest, Now: now}
	tests := map[string]func(*provideradapter.IssueRequest){
		"account":     func(value *provideradapter.IssueRequest) { value.Subject.AccountRef = "999999999999" },
		"environment": func(value *provideradapter.IssueRequest) { value.Subject.Environment = "staging" },
		"authorization digest": func(value *provideradapter.IssueRequest) {
			value.AuthorizationDigest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		},
		"provider release": func(value *provideradapter.IssueRequest) { value.Release = "aws.sts-read-session@2.0.0" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			request := base
			mutate(&request)
			before := len(client.inputs)
			if _, err := broker.Issue(context.Background(), request); err == nil || len(client.inputs) != before {
				t.Fatalf("substitution reached STS: %v", err)
			}
		})
	}
	client.output = assumed(now, "999999999999")
	if _, err := broker.Issue(context.Background(), base); err == nil {
		t.Fatal("cross-account STS identity was accepted")
	}
	client.output = assumed(now.Add(30*time.Minute), "123456789012")
	if _, err := broker.Issue(context.Background(), base); err == nil {
		t.Fatal("overlong STS material was accepted")
	}
}

func assumed(now time.Time, account string) *sts.AssumeRoleOutput {
	return &sts.AssumeRoleOutput{
		AssumedRoleUser: &ststypes.AssumedRoleUser{Arn: awssdk.String("arn:aws:sts::" + account + ":assumed-role/MisconfigSession/session")},
		Credentials:     &ststypes.Credentials{AccessKeyId: awssdk.String("ASIAFIXTURE"), SecretAccessKey: awssdk.String("secret"), SessionToken: awssdk.String("token"), Expiration: awssdk.Time(now.Add(MaximumTTL))},
	}
}
