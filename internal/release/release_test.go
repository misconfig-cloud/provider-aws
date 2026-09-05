package release

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestBuildVerifyAndTamper(t *testing.T) {
	repository, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	first, second := t.TempDir(), t.TempDir()
	options := Options{Version: "1.2.3", Commit: "0123456789abcdef", SourceDateEpoch: 1_700_000_000, Targets: []Target{{"linux", "amd64"}}}
	options.OutputDir = first
	manifest, err := Build(context.Background(), repository, options)
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.Artifacts) != 1 {
		t.Fatalf("artifacts=%d", len(manifest.Artifacts))
	}
	// The production verifier intentionally requires the full public matrix.
	manifestPath := filepath.Join(first, "manifest.json")
	encoded, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) == 0 {
		t.Fatal("manifest empty")
	}
	options.OutputDir = second
	secondManifest, err := Build(context.Background(), repository, options)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Artifacts[0].SHA256 != secondManifest.Artifacts[0].SHA256 {
		t.Fatal("release archive is not reproducible")
	}
	artifact := filepath.Join(first, manifest.Artifacts[0].Filename)
	file, err := os.OpenFile(artifact, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = file.WriteString("tamper"); err != nil {
		t.Fatal(err)
	}
	_ = file.Close()
	if err = verifyFile(first, File{manifest.Artifacts[0].Filename, manifest.Artifacts[0].SHA256, manifest.Artifacts[0].Size}); err == nil {
		t.Fatal("tamper accepted")
	}
}

func TestRejectsInvalidOptions(t *testing.T) {
	_, err := Build(context.Background(), ".", Options{Version: "latest", Commit: "x", OutputDir: t.TempDir(), SourceDateEpoch: 1})
	if err == nil {
		t.Fatal("invalid version accepted")
	}
}
