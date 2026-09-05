package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/misconfig-cloud/provider-aws/internal/release"
)

func main() {
	version := flag.String("version", "", "release version")
	commit := flag.String("commit", "", "source commit")
	output := flag.String("output", "dist", "artifact directory")
	verify := flag.String("verify", "", "verify an existing artifact directory")
	flag.Parse()
	if *verify != "" {
		if err := release.Verify(*verify); err != nil {
			fatal(err)
		}
		fmt.Printf("Verified provider release artifacts in %s.\n", *verify)
		return
	}
	epoch, err := strconv.ParseInt(strings.TrimSpace(os.Getenv("SOURCE_DATE_EPOCH")), 10, 64)
	if err != nil || epoch <= 0 {
		fatal(fmt.Errorf("SOURCE_DATE_EPOCH must be a positive Unix timestamp"))
	}
	manifest, err := release.Build(context.Background(), ".", release.Options{
		Version: strings.TrimSpace(*version), Commit: strings.TrimSpace(*commit),
		OutputDir: *output, SourceDateEpoch: epoch,
	})
	if err != nil {
		fatal(err)
	}
	fmt.Printf("Built provider-aws %s: %d platform artifacts.\n", manifest.Version, len(manifest.Artifacts))
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "release: %v\n", err)
	os.Exit(1)
}
