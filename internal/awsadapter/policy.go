package awsadapter

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	provideradapter "github.com/misconfig-cloud/provider-sdk"
)

const maximumInlinePolicyBytes = 2048

const requiredIdentityAction = "sts:GetCallerIdentity"

// supportedReadOperations is release data owned by the AWS adapter. Adding a
// provider or operation never changes the control plane's policy engine.
var supportedReadOperations = map[string]string{
	"aws.autoscaling.DescribeAutoScalingGroups":      "autoscaling:DescribeAutoScalingGroups",
	"aws.cloudformation.DescribeStacks":              "cloudformation:DescribeStacks",
	"aws.cloudformation.ListStacks":                  "cloudformation:ListStacks",
	"aws.ec2.DescribeAddresses":                      "ec2:DescribeAddresses",
	"aws.ec2.DescribeInstances":                      "ec2:DescribeInstances",
	"aws.ec2.DescribeNatGateways":                    "ec2:DescribeNatGateways",
	"aws.ec2.DescribeRegions":                        "ec2:DescribeRegions",
	"aws.ec2.DescribeSecurityGroups":                 "ec2:DescribeSecurityGroups",
	"aws.ec2.DescribeVolumes":                        "ec2:DescribeVolumes",
	"aws.ec2.DescribeVpcs":                           "ec2:DescribeVpcs",
	"aws.ecs.DescribeClusters":                       "ecs:DescribeClusters",
	"aws.ecs.DescribeServices":                       "ecs:DescribeServices",
	"aws.ecs.ListClusters":                           "ecs:ListClusters",
	"aws.ecs.ListServices":                           "ecs:ListServices",
	"aws.eks.DescribeCluster":                        "eks:DescribeCluster",
	"aws.eks.ListClusters":                           "eks:ListClusters",
	"aws.elasticloadbalancing.DescribeLoadBalancers": "elasticloadbalancing:DescribeLoadBalancers",
	"aws.iam.GetAccountSummary":                      "iam:GetAccountSummary",
	"aws.lambda.GetFunctionConfiguration":            "lambda:GetFunctionConfiguration",
	"aws.lambda.ListFunctions":                       "lambda:ListFunctions",
	"aws.rds.DescribeDBClusters":                     "rds:DescribeDBClusters",
	"aws.rds.DescribeDBInstances":                    "rds:DescribeDBInstances",
	"aws.resourcegroupstaggingapi.GetResources":      "tag:GetResources",
	"aws.s3.ListBuckets":                             "s3:ListAllMyBuckets",
	"aws.sts.GetCallerIdentity":                      "sts:GetCallerIdentity",
}

type policyDocument struct {
	Version   string            `json:"Version"`
	Statement []policyStatement `json:"Statement"`
}

type policyStatement struct {
	Effect   string   `json:"Effect"`
	Action   []string `json:"Action"`
	Resource string   `json:"Resource"`
}

// CompileSessionPolicy converts only the representable AWS subset of the
// signed provider-neutral authorization. Unsupported allowed operations are a
// hard error. Non-allow rules narrow the native credential further.
func CompileSessionPolicy(authorization provideradapter.Authorization, accountRef string) (string, error) {
	if err := authorization.Validate(); err != nil {
		return "", err
	}
	if authorization.Provider != Provider || authorization.AccountRef != accountRef {
		return "", errors.New("authorization target does not match AWS connection")
	}
	if err := validateAuthorizationScope(authorization, accountRef); err != nil {
		return "", err
	}

	allowed := map[string]struct{}{}
	denied := map[string]struct{}{}
	denyAll := false
	for _, rule := range authorization.Rules {
		if !appliesToAWS(rule.Providers) {
			continue
		}
		if rule.Effect == "allow" && len(rule.Operations) == 0 {
			return "", fmt.Errorf("rule %s grants an unbounded AWS operation set", rule.ID)
		}
		if rule.Effect == "allow" && !rootScope(rule.ResourcePrefixes, accountRef) {
			return "", fmt.Errorf("rule %s has a resource scope this release cannot enforce", rule.ID)
		}
		if rule.Effect != "allow" && len(rule.Operations) == 0 {
			denyAll = true
			continue
		}
		for _, operation := range rule.Operations {
			action, known := supportedReadOperations[operation]
			if !known {
				if rule.Effect == "allow" {
					return "", fmt.Errorf("rule %s allows unsupported AWS operation %s", rule.ID, operation)
				}
				// An operation omitted from every native Allow statement is already
				// denied by IAM. No provider capability is invented for it.
				continue
			}
			if rule.Effect == "allow" {
				allowed[action] = struct{}{}
			} else {
				denied[action] = struct{}{}
			}
		}
	}
	if len(allowed) == 0 {
		return "", errors.New("authorization contains no supported AWS read operation")
	}
	for action := range denied {
		delete(allowed, action)
	}
	if denyAll || len(allowed) == 0 {
		return "", errors.New("authorization denies every supported AWS operation")
	}
	// AWS permits GetCallerIdentity even when IAM denies it. Requiring the
	// signed ceiling to include that unavoidable provider operation prevents
	// the native credential from having an undeclared capability.
	if _, declared := allowed[requiredIdentityAction]; !declared {
		return "", errors.New("AWS authorization must explicitly allow sts:GetCallerIdentity")
	}

	document := policyDocument{Version: "2012-10-17"}
	if len(denied) > 0 {
		document.Statement = append(document.Statement, policyStatement{Effect: "Deny", Action: sortedKeys(denied), Resource: "*"})
	}
	document.Statement = append(document.Statement, policyStatement{Effect: "Allow", Action: sortedKeys(allowed), Resource: "*"})
	encoded, err := json.Marshal(document)
	if err != nil {
		return "", err
	}
	if len(encoded) > maximumInlinePolicyBytes {
		return "", errors.New("AWS inline session policy exceeds the provider limit")
	}
	return string(encoded), nil
}

func appliesToAWS(providers []string) bool {
	if len(providers) == 0 {
		return true
	}
	for _, provider := range providers {
		if provider == Provider {
			return true
		}
	}
	return false
}

func rootScope(prefixes []string, accountRef string) bool {
	root := "aws://" + accountRef
	for _, prefix := range prefixes {
		if strings.TrimSuffix(prefix, "/") != root {
			return false
		}
	}
	return true
}

// validateAuthorizationScope keeps the credential path and typed-action path
// separate. Read credentials still require the account root because AWS read
// APIs in this release are wildcard-only. Exact action resources may coexist
// in the signed profile ceiling only when an AWS typed-capability rule binds
// each resource to an action operation implemented by this adapter release.
// They are never copied into the read credential's IAM session policy.
func validateAuthorizationScope(authorization provideradapter.Authorization, accountRef string) error {
	root := "aws://" + accountRef
	typedResources := make(map[string]struct{})
	foundRoot := false

	for _, rule := range authorization.Rules {
		if !appliesToAWS(rule.Providers) || rule.Effect != "require_typed_capability" {
			continue
		}
		if len(rule.Operations) == 0 || len(rule.ResourcePrefixes) == 0 {
			return fmt.Errorf("rule %s does not bind an exact AWS typed action", rule.ID)
		}
		for _, operation := range rule.Operations {
			if operation != SetLambdaReservedConcurrencyOperation {
				return fmt.Errorf("rule %s requires unsupported AWS typed operation %s", rule.ID, operation)
			}
		}
		for _, resource := range rule.ResourcePrefixes {
			resource = strings.TrimSpace(resource)
			match := lambdaFunctionARNPattern.FindStringSubmatch(resource)
			if len(match) != 5 || match[3] != accountRef {
				return fmt.Errorf("rule %s has an AWS typed-action resource this release cannot enforce", rule.ID)
			}
			typedResources[resource] = struct{}{}
		}
	}

	for _, prefix := range authorization.ResourcePrefixes {
		prefix = strings.TrimSpace(prefix)
		if strings.TrimSuffix(prefix, "/") == root {
			foundRoot = true
			continue
		}
		if _, bound := typedResources[prefix]; !bound {
			return errors.New("AWS authorization contains a resource outside its exact typed-action rules")
		}
	}
	if !foundRoot {
		return errors.New("AWS wildcard-only read actions require the connected account root scope")
	}
	for resource := range typedResources {
		if !containsExact(authorization.ResourcePrefixes, resource) {
			return errors.New("AWS typed-action rule is outside the signed profile resource ceiling")
		}
	}
	return nil
}

func containsExact(values []string, expected string) bool {
	for _, value := range values {
		if strings.TrimSpace(value) == expected {
			return true
		}
	}
	return false
}

func sortedKeys(values map[string]struct{}) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}
