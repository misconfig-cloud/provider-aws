package awsadapter

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	provideradapter "github.com/misconfig-cloud/provider-sdk"
)

const (
	SetLambdaReservedConcurrencyCapability = "aws.lambda.reserved-concurrency@1.1.0"
	SetLambdaReservedConcurrencyOperation  = "aws.lambda.SetReservedConcurrency"
	ActionAuthorityTTL                     = 2 * time.Minute
)

var lambdaFunctionARNPattern = regexp.MustCompile(`^arn:(aws|aws-us-gov|aws-cn):lambda:([a-z0-9-]+):([0-9]{12}):function:([A-Za-z0-9-_]+)$`)

type LambdaClient interface {
	GetFunctionConcurrency(context.Context, *lambda.GetFunctionConcurrencyInput, ...func(*lambda.Options)) (*lambda.GetFunctionConcurrencyOutput, error)
	PutFunctionConcurrency(context.Context, *lambda.PutFunctionConcurrencyInput, ...func(*lambda.Options)) (*lambda.PutFunctionConcurrencyOutput, error)
	DeleteFunctionConcurrency(context.Context, *lambda.DeleteFunctionConcurrencyInput, ...func(*lambda.Options)) (*lambda.DeleteFunctionConcurrencyOutput, error)
}

type LambdaClientFactory func(region string, credentials awssdk.Credentials) LambdaClient

type Actions struct {
	Broker        Broker
	LambdaFactory LambdaClientFactory
}

type lambdaConcurrencyParameters struct {
	ReservedConcurrentExecutions *int32 `json:"reserved_concurrent_executions"`
	Remove                       bool   `json:"remove"`
}

type lambdaConcurrencyState struct {
	FunctionARN              string `json:"function_arn"`
	Before                   *int32 `json:"before"`
	After                    *int32 `json:"after"`
	ExecutionRequestID       string `json:"execution_request_id"`
	IndependentReadRequestID string `json:"independent_read_request_id,omitempty"`
}

func ActionCapabilities() []provideradapter.ActionCapability {
	return []provideradapter.ActionCapability{lambdaReservedConcurrencyCapability()}
}

func lambdaReservedConcurrencyCapability() provideradapter.ActionCapability {
	return provideradapter.ActionCapability{
		Ref:               SetLambdaReservedConcurrencyCapability,
		Operation:         SetLambdaReservedConcurrencyOperation,
		MaximumTTLSeconds: int64(ActionAuthorityTTL.Seconds()),
		Reversible:        true,
		Semantics:         &provideradapter.ActionSemantics{Protocol: provideradapter.ActionSemanticsProtocol, Effects: []provideradapter.ActionEffect{provideradapter.EffectWrite, provideradapter.EffectAvailabilityChange}},
		ParametersSchema: map[string]any{
			"type": "object", "additionalProperties": false,
			"properties": map[string]any{
				"reserved_concurrent_executions": map[string]any{"type": "integer", "minimum": 0},
				"remove":                         map[string]any{"type": "boolean"},
			},
			"description": "Set exactly one Lambda function reserved-concurrency limit, or remove the existing limit. Exactly one of reserved_concurrent_executions and remove=true is accepted.",
		},
		ExecutionSchema: map[string]any{
			"type": "object", "required": []string{"function_arn", "before", "after", "execution_request_id"},
		},
		VerificationSchema: map[string]any{
			"type": "object", "required": []string{"function_arn", "after", "independent_read_request_id"},
		},
	}
}

func (a Actions) ExecuteAction(ctx context.Context, request provideradapter.ExecuteActionRequest) (provideradapter.ActionExecution, error) {
	capability := lambdaReservedConcurrencyCapability()
	if err := request.Validate(capability); err != nil || request.Provider != Provider || request.Release != Release || request.Operation != SetLambdaReservedConcurrencyOperation {
		return provideradapter.ActionExecution{}, errors.New("AWS typed action contract is invalid")
	}
	config, region, functionName, parameters, err := a.prepare(request.Configuration, request.AccountRef, request.Resource, request.Parameters)
	if err != nil {
		return provideradapter.ActionExecution{}, err
	}
	policy, err := lambdaActionPolicy(request.Resource, parameters)
	if err != nil {
		return provideradapter.ActionExecution{}, err
	}
	client, identity, err := a.client(ctx, config, region, request.ActionID, "execute", policy)
	if err != nil {
		return provideradapter.ActionExecution{}, err
	}
	beforeOutput, err := client.GetFunctionConcurrency(ctx, &lambda.GetFunctionConcurrencyInput{FunctionName: &functionName})
	if err != nil {
		return provideradapter.ActionExecution{}, fmt.Errorf("read Lambda concurrency before action: %w", err)
	}
	state := lambdaConcurrencyState{FunctionARN: request.Resource, Before: beforeOutput.ReservedConcurrentExecutions}
	if parameters.Remove {
		output, err := client.DeleteFunctionConcurrency(ctx, &lambda.DeleteFunctionConcurrencyInput{FunctionName: &functionName})
		if err != nil {
			return provideradapter.ActionExecution{}, fmt.Errorf("remove Lambda reserved concurrency: %w", err)
		}
		state.ExecutionRequestID, _ = awsmiddleware.GetRequestIDMetadata(output.ResultMetadata)
	} else {
		output, err := client.PutFunctionConcurrency(ctx, &lambda.PutFunctionConcurrencyInput{FunctionName: &functionName, ReservedConcurrentExecutions: parameters.ReservedConcurrentExecutions})
		if err != nil {
			return provideradapter.ActionExecution{}, fmt.Errorf("set Lambda reserved concurrency: %w", err)
		}
		state.After = output.ReservedConcurrentExecutions
		state.ExecutionRequestID, _ = awsmiddleware.GetRequestIDMetadata(output.ResultMetadata)
	}
	if strings.TrimSpace(state.ExecutionRequestID) == "" {
		return provideradapter.ActionExecution{}, errors.New("AWS returned no action request identity")
	}
	encoded, _ := json.Marshal(state)
	digest, err := provideradapter.JSONDigest(encoded)
	if err != nil {
		return provideradapter.ActionExecution{}, err
	}
	return provideradapter.ActionExecution{ProviderReceipt: state.ExecutionRequestID, ExecutionIdentity: identity, ExecutedAt: request.Now.UTC(), Output: encoded, OutputDigest: digest}, nil
}

func (a Actions) VerifyAction(ctx context.Context, request provideradapter.VerifyActionRequest) (provideradapter.ActionVerification, error) {
	capability := lambdaReservedConcurrencyCapability()
	if err := request.Validate(capability); err != nil || request.Provider != Provider || request.Release != Release || request.Operation != SetLambdaReservedConcurrencyOperation {
		return provideradapter.ActionVerification{}, errors.New("AWS typed action verification contract is invalid")
	}
	config, region, functionName, parameters, err := a.prepare(request.Configuration, request.AccountRef, request.Resource, request.Parameters)
	if err != nil {
		return provideradapter.ActionVerification{}, err
	}
	client, _, err := a.client(ctx, config, region, request.ActionID, "verify", lambdaVerificationPolicy(request.Resource))
	if err != nil {
		return provideradapter.ActionVerification{}, err
	}
	output, err := client.GetFunctionConcurrency(ctx, &lambda.GetFunctionConcurrencyInput{FunctionName: &functionName})
	if err != nil {
		return provideradapter.ActionVerification{}, fmt.Errorf("independently read Lambda concurrency: %w", err)
	}
	requestID, _ := awsmiddleware.GetRequestIDMetadata(output.ResultMetadata)
	if strings.TrimSpace(requestID) == "" {
		return provideradapter.ActionVerification{}, errors.New("AWS returned no independent verification request identity")
	}
	state := "verified"
	if (parameters.Remove && output.ReservedConcurrentExecutions != nil) || (!parameters.Remove && !equalInt32(parameters.ReservedConcurrentExecutions, output.ReservedConcurrentExecutions)) {
		state = "failed"
	}
	evidence, _ := json.Marshal(lambdaConcurrencyState{FunctionARN: request.Resource, After: output.ReservedConcurrentExecutions, IndependentReadRequestID: requestID})
	digest, err := provideradapter.JSONDigest(evidence)
	if err != nil {
		return provideradapter.ActionVerification{}, err
	}
	return provideradapter.ActionVerification{State: state, VerifiedAt: request.Now.UTC(), VerifierRelease: Release + "/lambda-concurrency-readback@1", Evidence: evidence, EvidenceDigest: digest}, nil
}

func (a Actions) prepare(configuration json.RawMessage, accountRef, resource string, encodedParameters json.RawMessage) (configurationValue configuration, region, functionName string, parameters lambdaConcurrencyParameters, err error) {
	if a.Broker.Client == nil || a.LambdaFactory == nil {
		err = errors.New("AWS action adapter is not configured")
		return
	}
	configurationValue, err = decodeConfiguration(configuration, accountRef)
	if err != nil {
		return
	}
	match := lambdaFunctionARNPattern.FindStringSubmatch(strings.TrimSpace(resource))
	if len(match) != 5 || match[3] != accountRef {
		err = errors.New("Lambda function ARN is outside the connected AWS account")
		return
	}
	region, functionName = match[2], match[4]
	decoder := json.NewDecoder(bytes.NewReader(encodedParameters))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&parameters) != nil || decoder.Decode(&struct{}{}) == nil || (parameters.Remove == (parameters.ReservedConcurrentExecutions != nil)) || (parameters.ReservedConcurrentExecutions != nil && *parameters.ReservedConcurrentExecutions < 0) {
		err = errors.New("Lambda reserved concurrency parameters are invalid")
	}
	return
}

func (a Actions) client(ctx context.Context, config configuration, region, actionID, phase, policy string) (LambdaClient, string, error) {
	name := "misconfig-action-" + shortHash(actionID+"\x00"+phase)
	source := "misconfig-" + shortHash(actionID)
	output, err := a.Broker.assume(ctx, config, name, source, policy)
	if err != nil {
		return nil, "", err
	}
	if err := verifyAssumedIdentity(output.AssumedRoleUser, accountFromRole(config.RoleARN)); err != nil || output.Credentials == nil {
		return nil, "", errors.New("AWS action credentials have an invalid identity")
	}
	credentials := output.Credentials
	material := awssdk.Credentials{AccessKeyID: awssdk.ToString(credentials.AccessKeyId), SecretAccessKey: awssdk.ToString(credentials.SecretAccessKey), SessionToken: awssdk.ToString(credentials.SessionToken), CanExpire: true, Expires: awssdk.ToTime(credentials.Expiration), Source: "misconfig-typed-action"}
	if !material.HasKeys() || !material.Expires.After(a.Broker.now()) {
		return nil, "", errors.New("AWS action credentials are invalid or expired")
	}
	return a.LambdaFactory(region, material), awssdk.ToString(output.AssumedRoleUser.Arn), nil
}

func lambdaActionPolicy(resource string, parameters lambdaConcurrencyParameters) (string, error) {
	action := "lambda:PutFunctionConcurrency"
	if parameters.Remove {
		action = "lambda:DeleteFunctionConcurrency"
	}
	return compactPolicy(resource, []string{"lambda:GetFunctionConcurrency", action})
}

func lambdaVerificationPolicy(resource string) string {
	policy, _ := compactPolicy(resource, []string{"lambda:GetFunctionConcurrency"})
	return policy
}

func compactPolicy(resource string, actions []string) (string, error) {
	encoded, err := json.Marshal(map[string]any{"Version": "2012-10-17", "Statement": []map[string]any{{"Sid": "MisconfigExactTypedAction", "Effect": "Allow", "Action": actions, "Resource": resource}}})
	return string(encoded), err
}

func equalInt32(left, right *int32) bool {
	return left != nil && right != nil && *left == *right
}

func accountFromRole(roleARN string) string {
	match := roleARNPattern.FindStringSubmatch(roleARN)
	if len(match) == 4 {
		return match[2]
	}
	return ""
}
