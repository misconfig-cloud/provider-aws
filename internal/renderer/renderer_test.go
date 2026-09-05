package renderer

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/misconfig-cloud/provider-aws/internal/awsadapter"
	provideradapter "github.com/misconfig-cloud/provider-sdk"
)

func TestConfigureCreatesIsolatedCredentialProcessEnvironment(t *testing.T) {
	request := provideradapter.ConfigureRequest{Protocol: provideradapter.RendererProtocol, Release: awsadapter.Release, Provider: awsadapter.Provider, CredentialKind: awsadapter.CredentialKind, SessionID: "session-1", AccountRef: "123456789012", Environments: []string{"production"}, RuntimeDirectory: "/tmp/runtime with space", LeaseCommand: []string{"/opt/Misconfig Runtime/misconfig", "credential", "lease", "--active", "/tmp/active session"}}
	encoded, _ := json.Marshal(request)
	var output bytes.Buffer
	if err := Configure(bytes.NewReader(encoded), &output); err != nil {
		t.Fatal(err)
	}
	var rendered provideradapter.RenderedEnvironment
	if json.Unmarshal(output.Bytes(), &rendered) != nil || rendered.Set["AWS_PROFILE"] != "misconfig-session" || rendered.Set["AWS_EC2_METADATA_DISABLED"] != "true" || len(rendered.Files) != 1 || rendered.Files[0].Mode != 0o600 {
		t.Fatalf("unexpected environment: %#v", rendered)
	}
	config := rendered.Files[0].Content
	if !strings.Contains(config, `credential_process = "/opt/Misconfig Runtime/misconfig" credential lease --active "/tmp/active session"`) || strings.Contains(config, "secret") {
		t.Fatalf("unsafe credential_process config: %q", config)
	}
	wantedRemoved := map[string]bool{"AWS_ACCESS_KEY_ID": false, "AWS_SECRET_ACCESS_KEY": false, "AWS_SESSION_TOKEN": false, "AWS_WEB_IDENTITY_TOKEN_FILE": false}
	for _, name := range rendered.Remove {
		if _, ok := wantedRemoved[name]; ok {
			wantedRemoved[name] = true
		}
	}
	for name, found := range wantedRemoved {
		if !found {
			t.Fatalf("ambient credential variable %s was not removed", name)
		}
	}
}

func TestRenderReturnsExactCredentialProcessSchemaAndRejectsMalformedMaterial(t *testing.T) {
	expires := time.Date(2026, 9, 5, 12, 15, 0, 0, time.UTC)
	request := provideradapter.RenderRequest{Protocol: provideradapter.RendererProtocol, Release: awsadapter.Release, SessionID: "session-1", ActivePath: "/tmp/active", RuntimePath: "/tmp/renderer", Material: json.RawMessage(`{"Version":1,"AccessKeyId":"ASIAFIXTURE","SecretAccessKey":"secret","SessionToken":"token","Expiration":"2026-09-05T12:15:00Z"}`)}
	encoded, _ := json.Marshal(request)
	var output bytes.Buffer
	if err := Render(bytes.NewReader(encoded), &output); err != nil {
		t.Fatal(err)
	}
	var rendered provideradapter.RenderedMaterial
	if json.Unmarshal(output.Bytes(), &rendered) != nil {
		t.Fatal("rendered envelope is invalid")
	}
	var native struct {
		Version    int       `json:"Version"`
		Expiration time.Time `json:"Expiration"`
	}
	if json.Unmarshal([]byte(rendered.Stdout), &native) != nil || native.Version != 1 || !native.Expiration.Equal(expires) {
		t.Fatalf("native credential schema changed: %q", rendered.Stdout)
	}
	request.Material = json.RawMessage(`{"Version":1,"AccessKeyId":"ASIAFIXTURE","SecretAccessKey":"secret","SessionToken":""}`)
	encoded, _ = json.Marshal(request)
	if err := Render(bytes.NewReader(encoded), &bytes.Buffer{}); err == nil {
		t.Fatal("malformed material was accepted")
	}
}
