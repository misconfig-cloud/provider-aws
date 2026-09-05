package renderer

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/misconfig-cloud/provider-aws/internal/awsadapter"
	provideradapter "github.com/misconfig-cloud/provider-sdk"
)

func Configure(input io.Reader, output io.Writer) error {
	var request provideradapter.ConfigureRequest
	if decodeStrict(input, &request) != nil || request.Protocol != provideradapter.RendererProtocol ||
		request.Release != awsadapter.Release || request.Provider != awsadapter.Provider || request.CredentialKind != awsadapter.CredentialKind ||
		request.SessionID == "" || request.AccountRef == "" || len(request.Environments) != 1 || len(request.LeaseCommand) == 0 || request.RuntimeDirectory == "" {
		return errors.New("invalid AWS configure request")
	}
	process := strings.Join(quoteCommand(request.LeaseCommand), " ")
	config := "[profile misconfig-session]\ncredential_process = " + process + "\n"
	result := provideradapter.RenderedEnvironment{
		Remove: []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_SECURITY_TOKEN", "AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_ROLE_ARN", "AWS_CONTAINER_CREDENTIALS_FULL_URI", "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "AWS_SHARED_CREDENTIALS_FILE"},
		Set:    map[string]string{"AWS_PROFILE": "misconfig-session", "AWS_DEFAULT_PROFILE": "misconfig-session", "AWS_CONFIG_FILE": request.RuntimeDirectory + "/aws-config", "AWS_SDK_LOAD_CONFIG": "1", "AWS_EC2_METADATA_DISABLED": "true"},
		Files:  []provideradapter.RenderedFile{{Name: "aws-config", Content: config, Mode: 0o600}},
	}
	return json.NewEncoder(output).Encode(result)
}

func Render(input io.Reader, output io.Writer) error {
	var request provideradapter.RenderRequest
	if decodeStrict(input, &request) != nil || request.Protocol != provideradapter.RendererProtocol || request.Release != awsadapter.Release ||
		request.SessionID == "" || request.ActivePath == "" || request.RuntimePath == "" {
		return errors.New("invalid AWS render request")
	}
	var material struct {
		Version         int       `json:"Version"`
		AccessKeyID     string    `json:"AccessKeyId"`
		SecretAccessKey string    `json:"SecretAccessKey"`
		SessionToken    string    `json:"SessionToken"`
		Expiration      time.Time `json:"Expiration"`
	}
	if json.Unmarshal(request.Material, &material) != nil || material.Version != 1 || material.AccessKeyID == "" || material.SecretAccessKey == "" || material.SessionToken == "" || material.Expiration.IsZero() {
		return errors.New("invalid AWS process credential material")
	}
	native, err := json.Marshal(material)
	if err != nil {
		return err
	}
	return json.NewEncoder(output).Encode(provideradapter.RenderedMaterial{Stdout: string(native) + "\n"})
}

func decodeStrict(input io.Reader, target any) error {
	decoder := json.NewDecoder(io.LimitReader(input, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("trailing request data")
	}
	return nil
}

func quoteCommand(values []string) []string {
	quoted := make([]string, len(values))
	for index, value := range values {
		if value == "" {
			quoted[index] = `""`
			continue
		}
		if strings.ContainsAny(value, " \t\n\"\\") {
			var buffer bytes.Buffer
			buffer.WriteByte('"')
			for _, r := range value {
				if r == '\\' || r == '"' {
					buffer.WriteByte('\\')
				}
				buffer.WriteRune(r)
			}
			buffer.WriteByte('"')
			quoted[index] = buffer.String()
			continue
		}
		quoted[index] = value
	}
	return quoted
}

func ExampleConfiguration(command []string) string {
	return fmt.Sprintf("credential_process = %s", strings.Join(quoteCommand(command), " "))
}
