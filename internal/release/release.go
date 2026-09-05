package release

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

type Target struct {
	OS   string `json:"os"`
	Arch string `json:"arch"`
}
type Artifact struct {
	Target
	Filename string `json:"filename"`
	SHA256   string `json:"sha256"`
	Size     int64  `json:"size"`
}
type File struct {
	Filename string `json:"filename"`
	SHA256   string `json:"sha256"`
	Size     int64  `json:"size"`
}
type Manifest struct {
	SchemaVersion   int        `json:"schema_version"`
	Product         string     `json:"product"`
	Version         string     `json:"version"`
	Commit          string     `json:"commit"`
	SourceDateEpoch int64      `json:"source_date_epoch"`
	Artifacts       []Artifact `json:"artifacts"`
	SBOM            File       `json:"sbom"`
}
type Options struct {
	Version, Commit, OutputDir string
	SourceDateEpoch            int64
	Targets                    []Target
}

var defaultTargets = []Target{{"darwin", "amd64"}, {"darwin", "arm64"}, {"linux", "amd64"}, {"linux", "arm64"}}
var versionPattern = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?$`)

func Build(ctx context.Context, repository string, options Options) (Manifest, error) {
	if !versionPattern.MatchString(options.Version) || strings.TrimSpace(options.Commit) == "" || options.SourceDateEpoch <= 0 || strings.TrimSpace(options.OutputDir) == "" {
		return Manifest{}, errors.New("version, commit, source date epoch, and output are required")
	}
	var err error
	repository, err = filepath.Abs(repository)
	if err != nil {
		return Manifest{}, fmt.Errorf("resolve repository: %w", err)
	}
	output, err := filepath.Abs(options.OutputDir)
	if err != nil {
		return Manifest{}, fmt.Errorf("resolve output: %w", err)
	}
	if err := os.MkdirAll(output, 0o755); err != nil {
		return Manifest{}, err
	}
	targets := append([]Target(nil), options.Targets...)
	if len(targets) == 0 {
		targets = append(targets, defaultTargets...)
	}
	sort.Slice(targets, func(i, j int) bool { return targets[i].OS+"/"+targets[i].Arch < targets[j].OS+"/"+targets[j].Arch })
	seen := map[Target]bool{}
	for _, target := range targets {
		if !validTarget(target) || seen[target] {
			return Manifest{}, fmt.Errorf("invalid or duplicate target %s/%s", target.OS, target.Arch)
		}
		seen[target] = true
	}
	for _, name := range []string{"manifest.json", "checksums.txt", "sbom.spdx.json"} {
		if _, err := os.Stat(filepath.Join(output, name)); err == nil {
			return Manifest{}, fmt.Errorf("refusing to overwrite %s", name)
		}
	}
	work, err := os.MkdirTemp("", "provider-aws-release-")
	if err != nil {
		return Manifest{}, err
	}
	defer os.RemoveAll(work)
	manifest := Manifest{SchemaVersion: 1, Product: "misconfig-provider-aws", Version: options.Version, Commit: options.Commit, SourceDateEpoch: options.SourceDateEpoch}
	for _, target := range targets {
		filename := fmt.Sprintf("misconfig-provider-aws_%s_%s_%s.tar.gz", options.Version, target.OS, target.Arch)
		destination := filepath.Join(output, filename)
		if _, err := os.Stat(destination); err == nil {
			return Manifest{}, fmt.Errorf("refusing to overwrite %s", filename)
		}
		binary := filepath.Join(work, target.OS+"-"+target.Arch, "misconfig-provider-aws")
		if err := os.MkdirAll(filepath.Dir(binary), 0o755); err != nil {
			return Manifest{}, err
		}
		command := exec.CommandContext(ctx, "go", "build", "-trimpath", "-buildvcs=false", "-ldflags", "-s -w -buildid= -X main.version="+options.Version, "-o", binary, ".")
		command.Dir = repository
		command.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS="+target.OS, "GOARCH="+target.Arch)
		if encoded, err := command.CombinedOutput(); err != nil {
			return Manifest{}, fmt.Errorf("build %s/%s: %w: %s", target.OS, target.Arch, err, encoded)
		}
		files := []archiveFile{{"misconfig-provider-aws", binary, 0o755}, {"install.sh", filepath.Join(repository, "scripts", "install.sh"), 0o755}, {"uninstall.sh", filepath.Join(repository, "scripts", "uninstall.sh"), 0o755}, {"LICENSE", filepath.Join(repository, "LICENSE"), 0o644}, {"README.md", filepath.Join(repository, "README.md"), 0o644}, {"SECURITY.md", filepath.Join(repository, "SECURITY.md"), 0o644}}
		if err := writeArchive(destination, files, time.Unix(options.SourceDateEpoch, 0).UTC()); err != nil {
			return Manifest{}, err
		}
		digest, size, err := digestFile(destination)
		if err != nil {
			return Manifest{}, err
		}
		manifest.Artifacts = append(manifest.Artifacts, Artifact{Target: target, Filename: filename, SHA256: digest, Size: size})
	}
	sbom, err := buildSBOM(ctx, repository, manifest)
	if err != nil {
		return Manifest{}, err
	}
	manifest.SBOM, err = writeFile(output, "sbom.spdx.json", sbom)
	if err != nil {
		return Manifest{}, err
	}
	encoded, _ := json.MarshalIndent(manifest, "", "  ")
	encoded = append(encoded, '\n')
	if _, err := writeFile(output, "manifest.json", encoded); err != nil {
		return Manifest{}, err
	}
	if err := writeChecksums(output, manifest); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

func Verify(directory string) error {
	encoded, err := os.ReadFile(filepath.Join(directory, "manifest.json"))
	if err != nil {
		return err
	}
	var manifest Manifest
	if json.Unmarshal(encoded, &manifest) != nil || manifest.SchemaVersion != 1 || manifest.Product != "misconfig-provider-aws" || !versionPattern.MatchString(manifest.Version) || len(manifest.Artifacts) != 4 {
		return errors.New("invalid release manifest")
	}
	seen := map[string]bool{}
	seenTargets := map[Target]bool{}
	expectedTargets := map[Target]bool{}
	for _, target := range defaultTargets {
		expectedTargets[target] = true
	}
	if !safeName(manifest.SBOM.Filename) || manifest.SBOM.Filename != "sbom.spdx.json" {
		return errors.New("invalid SBOM manifest")
	}
	files := append([]File{{Filename: "manifest.json"}}, manifest.SBOM)
	for _, artifact := range manifest.Artifacts {
		if !safeName(artifact.Filename) || seen[artifact.Filename] || seenTargets[artifact.Target] || !expectedTargets[artifact.Target] {
			return errors.New("invalid artifact manifest")
		}
		seen[artifact.Filename] = true
		seenTargets[artifact.Target] = true
		files = append(files, File{artifact.Filename, artifact.SHA256, artifact.Size})
	}
	for _, file := range files[1:] {
		if err := verifyFile(directory, file); err != nil {
			return err
		}
	}
	checks, err := os.ReadFile(filepath.Join(directory, "checksums.txt"))
	if err != nil {
		return err
	}
	want := checksumText(manifest, sha256Hex(encoded))
	if string(checks) != want {
		return errors.New("checksum manifest does not match release manifest")
	}
	return nil
}

type archiveFile struct {
	Name, Path string
	Mode       int64
}

func writeArchive(destination string, files []archiveFile, timestamp time.Time) error {
	temporary, err := os.CreateTemp(filepath.Dir(destination), ".archive-")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)
	gzipWriter, _ := gzip.NewWriterLevel(temporary, gzip.BestCompression)
	gzipWriter.Header.ModTime = timestamp
	gzipWriter.Header.OS = 255
	tarWriter := tar.NewWriter(gzipWriter)
	for _, file := range files {
		body, err := os.ReadFile(file.Path)
		if err != nil {
			return err
		}
		header := &tar.Header{Name: file.Name, Mode: file.Mode, Size: int64(len(body)), ModTime: timestamp, AccessTime: timestamp, ChangeTime: timestamp, Uid: 0, Gid: 0, Uname: "", Gname: "", Format: tar.FormatPAX}
		if err = tarWriter.WriteHeader(header); err != nil {
			return err
		}
		if _, err = tarWriter.Write(body); err != nil {
			return err
		}
	}
	if err = tarWriter.Close(); err != nil {
		return err
	}
	if err = gzipWriter.Close(); err != nil {
		return err
	}
	if err = temporary.Close(); err != nil {
		return err
	}
	return os.Rename(name, destination)
}
func digestFile(path string) (string, int64, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer file.Close()
	hash := sha256.New()
	size, err := io.Copy(hash, file)
	return hex.EncodeToString(hash.Sum(nil)), size, err
}
func sha256Hex(value []byte) string { sum := sha256.Sum256(value); return hex.EncodeToString(sum[:]) }
func writeFile(directory, name string, body []byte) (File, error) {
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, body, 0o644); err != nil {
		return File{}, err
	}
	digest, size, err := digestFile(path)
	return File{name, digest, size}, err
}
func verifyFile(directory string, file File) error {
	if !safeName(file.Filename) || !validDigest(file.SHA256) || file.Size <= 0 {
		return errors.New("invalid release file")
	}
	digest, size, err := digestFile(filepath.Join(directory, file.Filename))
	if err != nil {
		return err
	}
	if digest != file.SHA256 || size != file.Size {
		return fmt.Errorf("release file %s changed", file.Filename)
	}
	return nil
}
func safeName(name string) bool {
	return name != "" && filepath.Base(name) == name && name != "." && name != ".."
}
func validTarget(target Target) bool {
	return (target.OS == "darwin" || target.OS == "linux") && (target.Arch == "amd64" || target.Arch == "arm64")
}
func validDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && value == strings.ToLower(value)
}
func checksumText(manifest Manifest, manifestDigest string) string {
	values := map[string]string{"manifest.json": manifestDigest, manifest.SBOM.Filename: manifest.SBOM.SHA256}
	for _, a := range manifest.Artifacts {
		values[a.Filename] = a.SHA256
	}
	names := make([]string, 0, len(values))
	for n := range values {
		names = append(names, n)
	}
	sort.Strings(names)
	var b strings.Builder
	for _, n := range names {
		fmt.Fprintf(&b, "%s  %s\n", values[n], n)
	}
	return b.String()
}
func writeChecksums(directory string, manifest Manifest) error {
	encoded, err := os.ReadFile(filepath.Join(directory, "manifest.json"))
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(directory, "checksums.txt"), []byte(checksumText(manifest, sha256Hex(encoded))), 0o644)
}

type module struct {
	Path, Version string
	Main          bool
}

func buildSBOM(ctx context.Context, repository string, manifest Manifest) ([]byte, error) {
	command := exec.CommandContext(ctx, "go", "list", "-m", "-json", "all")
	command.Dir = repository
	out, err := command.Output()
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(strings.NewReader(string(out)))
	packages := []map[string]any{}
	for {
		var m module
		if err := decoder.Decode(&m); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return nil, err
		}
		version := m.Version
		if m.Main {
			version = manifest.Version
		}
		packages = append(packages, map[string]any{"name": m.Path, "SPDXID": "SPDXRef-Package-" + sha256Hex([]byte(m.Path))[:16], "versionInfo": version, "downloadLocation": "NOASSERTION", "filesAnalyzed": false, "licenseConcluded": "NOASSERTION", "licenseDeclared": "NOASSERTION", "copyrightText": "NOASSERTION"})
	}
	sort.Slice(packages, func(i, j int) bool { return packages[i]["name"].(string) < packages[j]["name"].(string) })
	document := map[string]any{"spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT", "name": "misconfig-provider-aws-" + manifest.Version, "documentNamespace": "https://misconfig.cloud/spdx/provider-aws/" + manifest.Commit, "creationInfo": map[string]any{"created": time.Unix(manifest.SourceDateEpoch, 0).UTC().Format(time.RFC3339), "creators": []string{"Organization: Misconfig Cloud LLC"}}, "packages": packages}
	encoded, err := json.MarshalIndent(document, "", "  ")
	return append(encoded, '\n'), err
}
