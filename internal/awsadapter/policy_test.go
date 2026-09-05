package awsadapter

import (
	"encoding/json"
	"strings"
	"testing"

	provideradapter "github.com/misconfig-cloud/provider-sdk"
)

func TestCompileSessionPolicyMapsOnlyExplicitReadCeiling(t *testing.T) {
	authorization := fixtureAuthorization()
	authorization.Rules = append(authorization.Rules,
		provideradapter.AuthorizationRule{ID: "deny-volumes", Effect: "deny", Providers: []string{"aws"}, Operations: []string{"aws.ec2.DescribeVolumes"}},
		provideradapter.AuthorizationRule{ID: "other-provider", Effect: "allow", Providers: []string{"unfamiliar-edge"}, Operations: []string{"unfamiliar-edge.Read"}},
	)
	encoded, err := CompileSessionPolicy(authorization, "123456789012")
	if err != nil {
		t.Fatal(err)
	}
	var document policyDocument
	if err := json.Unmarshal([]byte(encoded), &document); err != nil {
		t.Fatal(err)
	}
	if len(document.Statement) != 2 || document.Statement[0].Effect != "Deny" || document.Statement[1].Effect != "Allow" ||
		strings.Join(document.Statement[0].Action, ",") != "ec2:DescribeVolumes" ||
		strings.Join(document.Statement[1].Action, ",") != "ec2:DescribeInstances,sts:GetCallerIdentity" {
		t.Fatalf("unexpected AWS session policy: %#v", document)
	}
}

func TestCompileSessionPolicyFailsClosedOnWidening(t *testing.T) {
	tests := map[string]func(*provideradapter.Authorization){
		"unknown allowed operation": func(value *provideradapter.Authorization) {
			value.Rules[0].Operations = []string{"aws.ec2.TerminateInstances"}
		},
		"unbounded allowed operations": func(value *provideradapter.Authorization) {
			value.Rules[0].Operations = nil
		},
		"narrow authorization resource": func(value *provideradapter.Authorization) {
			value.ResourcePrefixes = []string{"arn:aws:ec2:us-east-1:123456789012:instance/i-1"}
		},
		"narrow rule resource": func(value *provideradapter.Authorization) {
			value.Rules[0].ResourcePrefixes = []string{"aws://123456789012/instance/i-1"}
		},
		"account substitution": func(value *provideradapter.Authorization) {
			value.AccountRef = "999999999999"
		},
		"provider substitution": func(value *provideradapter.Authorization) {
			value.Provider = "unfamiliar-edge"
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			authorization := fixtureAuthorization()
			mutate(&authorization)
			if _, err := CompileSessionPolicy(authorization, "123456789012"); err == nil {
				t.Fatal("widened authorization was accepted")
			}
		})
	}
}

func TestApprovalOrTypedRuleNeverBecomesNativeAuthority(t *testing.T) {
	for _, effect := range []string{"require_approval", "require_typed_capability", "stop_session"} {
		t.Run(effect, func(t *testing.T) {
			authorization := fixtureAuthorization()
			authorization.Rules = []provideradapter.AuthorizationRule{
				{ID: "allow", Effect: "allow", Providers: []string{"aws"}, Operations: []string{"aws.ec2.DescribeInstances"}},
				{ID: "narrow", Effect: effect, Providers: []string{"aws"}, Operations: []string{"aws.ec2.DescribeInstances"}},
			}
			if _, err := CompileSessionPolicy(authorization, "123456789012"); err == nil {
				t.Fatal("operation requiring an additional decision remained in native credentials")
			}
		})
	}
}

func TestUnavoidableAWSIdentityOperationMustBeDeclared(t *testing.T) {
	authorization := fixtureAuthorization()
	authorization.Rules[0].Operations = []string{"aws.ec2.DescribeInstances"}
	if _, err := CompileSessionPolicy(authorization, "123456789012"); err == nil || !strings.Contains(err.Error(), "GetCallerIdentity") {
		t.Fatalf("undeclared provider bootstrap capability was accepted: %v", err)
	}
}

func TestCompileSessionPolicyKeepsExactTypedActionOutsideReadCredentials(t *testing.T) {
	authorization := fixtureAuthorization()
	functionARN := "arn:aws:lambda:us-east-1:123456789012:function:checkout"
	authorization.ResourcePrefixes = append(authorization.ResourcePrefixes, functionARN)
	authorization.Rules = append(authorization.Rules, provideradapter.AuthorizationRule{
		ID: "typed-lambda-concurrency", Effect: "require_typed_capability", Providers: []string{"aws"},
		Operations: []string{SetLambdaReservedConcurrencyOperation}, ResourcePrefixes: []string{functionARN},
	})

	encoded, err := CompileSessionPolicy(authorization, "123456789012")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(encoded, "lambda:") || strings.Contains(encoded, functionARN) {
		t.Fatalf("typed action leaked into read credentials: %s", encoded)
	}
	if !strings.Contains(encoded, "sts:GetCallerIdentity") {
		t.Fatalf("read credential lost its declared bootstrap capability: %s", encoded)
	}
}

func TestCompileSessionPolicyRejectsUnboundOrUnrepresentableTypedActionScope(t *testing.T) {
	functionARN := "arn:aws:lambda:us-east-1:123456789012:function:checkout"
	tests := map[string]func(*provideradapter.Authorization){
		"unbound extra resource": func(value *provideradapter.Authorization) {
			value.ResourcePrefixes = append(value.ResourcePrefixes, functionARN)
		},
		"typed rule outside ceiling": func(value *provideradapter.Authorization) {
			value.Rules = append(value.Rules, provideradapter.AuthorizationRule{ID: "typed", Effect: "require_typed_capability", Providers: []string{"aws"}, Operations: []string{SetLambdaReservedConcurrencyOperation}, ResourcePrefixes: []string{functionARN}})
		},
		"unknown typed operation": func(value *provideradapter.Authorization) {
			value.ResourcePrefixes = append(value.ResourcePrefixes, functionARN)
			value.Rules = append(value.Rules, provideradapter.AuthorizationRule{ID: "typed", Effect: "require_typed_capability", Providers: []string{"aws"}, Operations: []string{"aws.ec2.TerminateInstances"}, ResourcePrefixes: []string{functionARN}})
		},
		"wildcard function resource": func(value *provideradapter.Authorization) {
			resource := "arn:aws:lambda:us-east-1:123456789012:function:*"
			value.ResourcePrefixes = append(value.ResourcePrefixes, resource)
			value.Rules = append(value.Rules, provideradapter.AuthorizationRule{ID: "typed", Effect: "require_typed_capability", Providers: []string{"aws"}, Operations: []string{SetLambdaReservedConcurrencyOperation}, ResourcePrefixes: []string{resource}})
		},
		"cross-account function resource": func(value *provideradapter.Authorization) {
			resource := "arn:aws:lambda:us-east-1:999999999999:function:checkout"
			value.ResourcePrefixes = append(value.ResourcePrefixes, resource)
			value.Rules = append(value.Rules, provideradapter.AuthorizationRule{ID: "typed", Effect: "require_typed_capability", Providers: []string{"aws"}, Operations: []string{SetLambdaReservedConcurrencyOperation}, ResourcePrefixes: []string{resource}})
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			authorization := fixtureAuthorization()
			mutate(&authorization)
			if _, err := CompileSessionPolicy(authorization, "123456789012"); err == nil {
				t.Fatal("unrepresentable typed action scope was accepted")
			}
		})
	}
}

func fixtureAuthorization() provideradapter.Authorization {
	return provideradapter.Authorization{
		ProfileDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		PolicyRelease: "policy-1", Provider: "aws", AccountRef: "123456789012",
		Environments: []string{"production"}, ResourcePrefixes: []string{"aws://123456789012"},
		Rules: []provideradapter.AuthorizationRule{{ID: "read", Effect: "allow", Providers: []string{"aws"}, Operations: []string{"aws.sts.GetCallerIdentity", "aws.ec2.DescribeInstances"}, ResourcePrefixes: []string{"aws://123456789012"}}},
	}
}
