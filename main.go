package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/misconfig-cloud/provider-aws/internal/awsadapter"
	"github.com/misconfig-cloud/provider-aws/internal/renderer"
	provideradapter "github.com/misconfig-cloud/provider-sdk"
)

const publisherKeyID = "misconfig-aws-2026-v5"

var version = "dev"

func main() {
	if len(os.Args) < 2 {
		log.Fatal("serve, configure, render, keygen, or sign-manifest is required")
	}
	switch os.Args[1] {
	case "version", "--version":
		fmt.Println(version)
	case "serve":
		serve()
	case "configure":
		if err := renderer.Configure(os.Stdin, os.Stdout); err != nil {
			log.Fatal(err)
		}
	case "render":
		if err := renderer.Render(os.Stdin, os.Stdout); err != nil {
			log.Fatal(err)
		}
	case "keygen":
		keygen(os.Args[2:])
	case "sign-manifest":
		signManifest(os.Args[2:])
	default:
		log.Fatalf("unknown command %q", os.Args[1])
	}
}

func serve() {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	awsConfig, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		log.Fatal(err)
	}
	implementation := awsadapter.Broker{Client: sts.NewFromConfig(awsConfig), BrokerPrincipalARN: strings.TrimSpace(os.Getenv("MISCONFIG_AWS_BROKER_PRINCIPAL_ARN"))}
	actions := awsadapter.Actions{Broker: implementation, LambdaFactory: func(region string, material aws.Credentials) awsadapter.LambdaClient {
		configuration := awsConfig.Copy()
		configuration.Region = region
		configuration.Credentials = aws.NewCredentialsCache(credentials.NewStaticCredentialsProvider(material.AccessKeyID, material.SecretAccessKey, material.SessionToken))
		return lambda.NewFromConfig(configuration)
	}}
	handler, err := (&provideradapter.HTTPHandler{Implementation: implementation, Actions: actions, SharedSecret: strings.TrimSpace(os.Getenv("MISCONFIG_ADAPTER_SHARED_SECRET")), ManifestDigest: strings.TrimSpace(os.Getenv("MISCONFIG_ADAPTER_MANIFEST_DIGEST")), Release: awsadapter.Release}).Handler()
	if err != nil {
		log.Fatal(err)
	}
	address := strings.TrimSpace(os.Getenv("MISCONFIG_HTTP_ADDRESS"))
	if address == "" {
		address = ":8090"
	}
	server := &http.Server{Addr: address, Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 30 * time.Second}
	log.Fatal(server.ListenAndServe())
}

func keygen(args []string) {
	flags := flag.NewFlagSet("keygen", flag.ExitOnError)
	privatePath := flags.String("private-key-file", "", "new private key file")
	publicPath := flags.String("public-key-file", "", "new public key file")
	_ = flags.Parse(args)
	if err := generatePublisherKey(strings.TrimSpace(*privatePath), strings.TrimSpace(*publicPath)); err != nil {
		log.Fatal(err)
	}
}

func generatePublisherKey(privatePath, publicPath string) error {
	if privatePath == "" || publicPath == "" || privatePath == publicPath {
		return errors.New("distinct private and public key files are required")
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	privateFile, err := os.OpenFile(privatePath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err = privateFile.WriteString(base64.RawURLEncoding.EncodeToString(privateKey) + "\n"); err == nil {
		err = privateFile.Close()
	} else {
		_ = privateFile.Close()
	}
	if err != nil {
		_ = os.Remove(privatePath)
		return err
	}
	publicFile, err := os.OpenFile(publicPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		_ = os.Remove(privatePath)
		return err
	}
	if _, err = publicFile.WriteString(base64.RawURLEncoding.EncodeToString(publicKey) + "\n"); err == nil {
		err = publicFile.Close()
	} else {
		_ = publicFile.Close()
	}
	if err != nil {
		_ = os.Remove(privatePath)
		_ = os.Remove(publicPath)
		return err
	}
	return nil
}

type repeatedFlag []string

func (r *repeatedFlag) String() string         { return strings.Join(*r, ",") }
func (r *repeatedFlag) Set(value string) error { *r = append(*r, value); return nil }

func signManifest(args []string) {
	flags := flag.NewFlagSet("sign-manifest", flag.ExitOnError)
	endpoint := flags.String("endpoint", "", "HTTPS broker endpoint")
	privatePath := flags.String("private-key-file", "", "publisher private key file")
	var artifactFlags repeatedFlag
	flags.Var(&artifactFlags, "artifact", "renderer artifact os/arch=sha256:digest")
	_ = flags.Parse(args)
	artifacts, err := parseArtifacts(artifactFlags)
	if err != nil {
		log.Fatal(err)
	}
	encoded, err := os.ReadFile(*privatePath)
	if err != nil {
		log.Fatal(err)
	}
	privateKey, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(string(encoded)))
	if err != nil || len(privateKey) != ed25519.PrivateKeySize {
		log.Fatal("invalid private key")
	}
	credential := provideradapter.Credential{Kind: awsadapter.CredentialKind, MaximumTTLSeconds: int64(awsadapter.MaximumTTL.Seconds()), RevocationSemantics: awsadapter.RevocationSemantics, PayloadSchema: map[string]any{"type": "object", "required": []string{"Version", "AccessKeyId", "SecretAccessKey", "SessionToken", "Expiration"}}}
	renderer := provideradapter.Renderer{Protocol: provideradapter.RendererProtocol, Executable: "misconfig-provider-aws", Artifacts: artifacts, SensitiveEnvironment: []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_SECURITY_TOKEN", "AWS_PROFILE", "AWS_DEFAULT_PROFILE", "AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE", "AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_ROLE_ARN", "AWS_CONTAINER_CREDENTIALS_FULL_URI", "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI"}}
	manifest := provideradapter.Manifest{
		Protocol: provideradapter.ManifestProtocol, Publisher: provideradapter.Publisher{ID: "misconfig-cloud", KeyID: publisherKeyID}, Compatibility: provideradapter.Compatibility{Protocol: provideradapter.ManifestProtocol, Major: 2},
		Release: awsadapter.Release, Provider: awsadapter.Provider,
		ConfigurationSchema: map[string]any{"type": "object", "required": []string{"role_arn"}, "properties": map[string]any{"role_arn": map[string]any{"type": "string", "title": "Role ARN"}, "external_id": map[string]any{"type": "string", "title": "External ID", "description": "Optional. Misconfig generates one when omitted."}}},
		Credential:          &credential,
		Renderer:            &renderer,
		Broker:              provideradapter.Broker{Protocol: provideradapter.BrokerProtocol, Endpoint: *endpoint},
		Actions:             awsadapter.ActionCapabilities(),
	}
	signed, err := provideradapter.Sign(manifest, ed25519.PrivateKey(privateKey))
	if err != nil {
		log.Fatal(err)
	}
	if err := json.NewEncoder(os.Stdout).Encode(signed); err != nil {
		log.Fatal(err)
	}
}

func parseArtifacts(values []string) ([]provideradapter.RendererArtifact, error) {
	result := make([]provideradapter.RendererArtifact, 0, len(values))
	for _, value := range values {
		platform, digest, ok := strings.Cut(strings.TrimSpace(value), "=")
		operatingSystem, architecture, platformOK := strings.Cut(platform, "/")
		if !ok || !platformOK || operatingSystem == "" || architecture == "" || digest == "" {
			return nil, fmt.Errorf("artifact must be os/arch=sha256:digest")
		}
		result = append(result, provideradapter.RendererArtifact{OS: operatingSystem, Arch: architecture, Digest: digest})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].OS+"/"+result[i].Arch < result[j].OS+"/"+result[j].Arch })
	return result, nil
}
