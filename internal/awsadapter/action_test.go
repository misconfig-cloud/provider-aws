package awsadapter

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/smithy-go/middleware"
	provideradapter "github.com/misconfig-cloud/provider-sdk"
)

type fixtureLambda struct {
	concurrency *int32
	gets        int
	puts        int
	deletes     int
}

func (f *fixtureLambda) GetFunctionConcurrency(_ context.Context, _ *lambda.GetFunctionConcurrencyInput, _ ...func(*lambda.Options)) (*lambda.GetFunctionConcurrencyOutput, error) {
	f.gets++
	metadata := middleware.Metadata{}
	awsmiddleware.SetRequestIDMetadata(&metadata, "lambda-get-"+string(rune('0'+f.gets)))
	return &lambda.GetFunctionConcurrencyOutput{ReservedConcurrentExecutions: cloneInt32(f.concurrency), ResultMetadata: metadata}, nil
}

func (f *fixtureLambda) PutFunctionConcurrency(_ context.Context, input *lambda.PutFunctionConcurrencyInput, _ ...func(*lambda.Options)) (*lambda.PutFunctionConcurrencyOutput, error) {
	f.puts++
	f.concurrency = cloneInt32(input.ReservedConcurrentExecutions)
	metadata := middleware.Metadata{}
	awsmiddleware.SetRequestIDMetadata(&metadata, "lambda-put-1")
	return &lambda.PutFunctionConcurrencyOutput{ReservedConcurrentExecutions: cloneInt32(f.concurrency), ResultMetadata: metadata}, nil
}

func (f *fixtureLambda) DeleteFunctionConcurrency(_ context.Context, _ *lambda.DeleteFunctionConcurrencyInput, _ ...func(*lambda.Options)) (*lambda.DeleteFunctionConcurrencyOutput, error) {
	f.deletes++
	f.concurrency = nil
	metadata := middleware.Metadata{}
	awsmiddleware.SetRequestIDMetadata(&metadata, "lambda-delete-1")
	return &lambda.DeleteFunctionConcurrencyOutput{ResultMetadata: metadata}, nil
}

func TestLambdaConcurrencyActionExecutesAndIndependentlyVerifiesExactResource(t *testing.T) {
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	stsClient := &fixtureSTS{output: assumed(now, "123456789012")}
	lambdaClient := &fixtureLambda{concurrency: awssdk.Int32(5)}
	regions := []string{}
	actions := Actions{
		Broker: Broker{Client: stsClient, BrokerPrincipalARN: "arn:aws:iam::999999999999:role/MisconfigBroker", Now: func() time.Time { return now }},
		LambdaFactory: func(region string, credentials awssdk.Credentials) LambdaClient {
			if !credentials.HasKeys() || credentials.Source != "misconfig-typed-action" {
				t.Fatalf("temporary action credentials are incomplete: %#v", credentials)
			}
			regions = append(regions, region)
			return lambdaClient
		},
	}
	request := fixtureLambdaActionRequest(t, now, json.RawMessage(`{"reserved_concurrent_executions":12}`))
	execution, err := actions.ExecuteAction(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if execution.ProviderReceipt != "lambda-put-1" || lambdaClient.puts != 1 || lambdaClient.gets != 1 || lambdaClient.deletes != 0 {
		t.Fatalf("unexpected execution: %#v client=%#v", execution, lambdaClient)
	}
	verification, err := actions.VerifyAction(context.Background(), fixtureLambdaVerificationRequest(request, execution, now.Add(time.Second)))
	if err != nil || verification.State != "verified" || lambdaClient.gets != 2 {
		t.Fatalf("unexpected verification: %#v err=%v", verification, err)
	}
	if len(regions) != 2 || regions[0] != "eu-central-1" || regions[1] != "eu-central-1" || len(stsClient.inputs) != 2 {
		t.Fatalf("action escaped its region or did not separate execution and verification: regions=%v inputs=%d", regions, len(stsClient.inputs))
	}
	executionPolicy := awssdk.ToString(stsClient.inputs[0].Policy)
	verificationPolicy := awssdk.ToString(stsClient.inputs[1].Policy)
	if !strings.Contains(executionPolicy, `"lambda:PutFunctionConcurrency"`) || !strings.Contains(executionPolicy, request.Resource) || strings.Contains(verificationPolicy, "PutFunctionConcurrency") || !strings.Contains(verificationPolicy, `"lambda:GetFunctionConcurrency"`) {
		t.Fatalf("action policies are not exact: execute=%s verify=%s", executionPolicy, verificationPolicy)
	}
}

func TestLambdaConcurrencyActionRemovesLimitAndVerificationDetectsDrift(t *testing.T) {
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	stsClient := &fixtureSTS{output: assumed(now, "123456789012")}
	lambdaClient := &fixtureLambda{concurrency: awssdk.Int32(7)}
	actions := Actions{Broker: Broker{Client: stsClient, BrokerPrincipalARN: "arn:aws:iam::999999999999:role/MisconfigBroker", Now: func() time.Time { return now }}, LambdaFactory: func(string, awssdk.Credentials) LambdaClient { return lambdaClient }}
	request := fixtureLambdaActionRequest(t, now, json.RawMessage(`{"remove":true}`))
	execution, err := actions.ExecuteAction(context.Background(), request)
	if err != nil || lambdaClient.deletes != 1 || lambdaClient.concurrency != nil {
		t.Fatalf("remove failed: execution=%#v client=%#v err=%v", execution, lambdaClient, err)
	}
	lambdaClient.concurrency = awssdk.Int32(3)
	verification, err := actions.VerifyAction(context.Background(), fixtureLambdaVerificationRequest(request, execution, now.Add(time.Second)))
	if err != nil || verification.State != "failed" {
		t.Fatalf("drift was not reported as failed verification: %#v err=%v", verification, err)
	}
}

func TestLambdaConcurrencyActionRejectsScopeAndParameterSubstitutionBeforeAWS(t *testing.T) {
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	stsClient := &fixtureSTS{output: assumed(now, "123456789012")}
	actions := Actions{Broker: Broker{Client: stsClient, BrokerPrincipalARN: "arn:aws:iam::999999999999:role/MisconfigBroker", Now: func() time.Time { return now }}, LambdaFactory: func(string, awssdk.Credentials) LambdaClient { return &fixtureLambda{} }}
	tests := map[string]func(*provideradapter.ExecuteActionRequest){
		"cross account resource": func(request *provideradapter.ExecuteActionRequest) {
			request.Resource = "arn:aws:lambda:eu-central-1:999999999999:function:checkout"
		},
		"qualified alias": func(request *provideradapter.ExecuteActionRequest) { request.Resource += ":live" },
		"unknown parameter": func(request *provideradapter.ExecuteActionRequest) {
			request.Parameters = json.RawMessage(`{"reserved_concurrent_executions":12,"force":true}`)
		},
		"ambiguous mutation": func(request *provideradapter.ExecuteActionRequest) {
			request.Parameters = json.RawMessage(`{"reserved_concurrent_executions":12,"remove":true}`)
		},
		"negative limit": func(request *provideradapter.ExecuteActionRequest) {
			request.Parameters = json.RawMessage(`{"reserved_concurrent_executions":-1}`)
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			request := fixtureLambdaActionRequest(t, now, json.RawMessage(`{"reserved_concurrent_executions":12}`))
			mutate(&request)
			if _, err := actions.ExecuteAction(context.Background(), request); err == nil || len(stsClient.inputs) != 0 {
				t.Fatalf("unsafe action reached AWS: %v", err)
			}
		})
	}
}

func fixtureLambdaActionRequest(t *testing.T, now time.Time, parameters json.RawMessage) provideradapter.ExecuteActionRequest {
	t.Helper()
	capability := lambdaReservedConcurrencyCapability()
	capabilityDigest, err := provideradapter.ActionCapabilityDigest(capability)
	if err != nil {
		t.Fatal(err)
	}
	actionDigest, err := provideradapter.ActionDigest(capabilityDigest, capability.Operation, "arn:aws:lambda:eu-central-1:123456789012:function:checkout", "production", parameters)
	if err != nil {
		t.Fatal(err)
	}
	return provideradapter.ExecuteActionRequest{
		RequestID: "action-1:execute", ConnectionID: "connection-1", Provider: Provider, Release: Release, AccountRef: "123456789012",
		Configuration: json.RawMessage(`{"role_arn":"arn:aws:iam::123456789012:role/MisconfigSession","external_id":"misconfig-fixed-external-id"}`),
		Subject:       provideradapter.Subject{TenantID: "tenant-1", ActorID: "actor-1", DeviceID: "device-1", SessionID: "session-1", ProfileID: "profile-1", AccountRef: "123456789012", Environment: "production"},
		CapabilityRef: capability.Ref, CapabilityDigest: capabilityDigest, ActionID: "action-1", ActionDigest: actionDigest,
		Operation: capability.Operation, Resource: "arn:aws:lambda:eu-central-1:123456789012:function:checkout", Environment: "production", Parameters: parameters,
		Authority: provideradapter.ActionAuthority{ID: "action-1", ActionDigest: actionDigest, CapabilityDigest: capabilityDigest, ApprovedBy: "operator-1", ApprovedAt: now.Add(-time.Second), ExpiresAt: now.Add(ActionAuthorityTTL)}, Now: now,
	}
}

func fixtureLambdaVerificationRequest(executionRequest provideradapter.ExecuteActionRequest, execution provideradapter.ActionExecution, now time.Time) provideradapter.VerifyActionRequest {
	return provideradapter.VerifyActionRequest{
		RequestID: executionRequest.ActionID + ":verify", ConnectionID: executionRequest.ConnectionID, Provider: executionRequest.Provider, Release: executionRequest.Release,
		AccountRef: executionRequest.AccountRef, Configuration: executionRequest.Configuration, Subject: executionRequest.Subject,
		CapabilityRef: executionRequest.CapabilityRef, CapabilityDigest: executionRequest.CapabilityDigest, ActionID: executionRequest.ActionID,
		ActionDigest: executionRequest.ActionDigest, Operation: executionRequest.Operation, Resource: executionRequest.Resource,
		Environment: executionRequest.Environment, Parameters: executionRequest.Parameters, Execution: execution, Now: now,
	}
}

func cloneInt32(value *int32) *int32 {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}
