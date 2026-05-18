package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"
)

const (
	binaryName = "ghost-sso-proxy"
	mainPkg    = "./cmd/"
	outDir     = "bin"
)

// Build compiles the binary for the current OS and architecture.
// Output: bin/ghost-sso-proxy (or bin/ghost-sso-proxy.exe on Windows).
func Build() error {
	mg.Deps(Tidy)
	return build(runtime.GOOS, runtime.GOARCH)
}

// BuildLinux cross-compiles a static binary for linux/amd64.
// This is the target used by the Dockerfile for the container image.
func BuildLinux() error {
	mg.Deps(Tidy)
	return build("linux", "amd64")
}

// Tidy runs go mod tidy to ensure go.sum is up to date.
func Tidy() error {
	fmt.Println(">> go mod tidy")
	return sh.Run("go", "mod", "tidy")
}

// Clean removes all build artifacts from the bin/ directory.
func Clean() error {
	fmt.Println(">> cleaning", outDir)
	return os.RemoveAll(outDir)
}

// build performs the actual compilation with CGO disabled and trims debug paths.
func build(goos, goarch string) error {
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return fmt.Errorf("creating output directory: %w", err)
	}

	out := filepath.Join(outDir, binaryName)
	if goos == "windows" {
		out += ".exe"
	}

	fmt.Printf(">> building %s/%s → %s\n", goos, goarch, out)

	env := map[string]string{
		"GOOS":        goos,
		"GOARCH":      goarch,
		"CGO_ENABLED": "0",
	}

	return sh.RunWithV(env, "go", "build",
		"-trimpath",
		"-ldflags", ldflags(),
		"-o", out,
		mainPkg,
	)
}

// ldflags returns linker flags that embed the git commit and build time.
func ldflags() string {
	commit, _ := sh.Output("git", "rev-parse", "--short", "HEAD")
	if commit == "" {
		commit = "unknown"
	}
	pkg := "github.com/safaci2000/ghost-sso-proxy/config"
	return fmt.Sprintf("-s -w -X %s.GitCommit=%s", pkg, commit)
}
