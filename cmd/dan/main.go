package main

import (
	"fmt"
	"os"
	"path/filepath"

	"dan/internal/danapp"
)

func main() {
	root, err := detectProjectRoot()
	if err != nil {
		fatalf("detect project root: %v", err)
	}

	opts, cfg, err := danapp.ParseCLI(root)
	if err != nil {
		fatalf("%v", err)
	}

	app, err := danapp.NewApp(cfg)
	if err != nil {
		fatalf("init app: %v", err)
	}

	if err := app.Run(opts); err != nil {
		fatalf("%v", err)
	}
}

func detectProjectRoot() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("get executable: %w", err)
	}
	exeDir := filepath.Dir(exe)
	root := filepath.Join(exeDir, "..")

	cwd, err := mustGetwd()
	if err != nil {
		return root, nil
	}

	// Prefer cwd if it looks like a valid project root
	if _, err := os.Stat(filepath.Join(cwd, "web_config.json")); err == nil {
		return cwd, nil
	}

	return root, nil
}

func mustGetwd() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("get working directory: %w", err)
	}
	return wd, nil
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
