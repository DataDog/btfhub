package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strconv"

	"github.com/kfcampbell/ghinstallation"
)

func main() {
	if err := run(); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	installationID, err := strconv.ParseInt(os.Getenv("GITHUB_INSTALLATION_ID"), 10, 64)
	if err != nil {
		return fmt.Errorf("parse installation ID: %w", err)
	}

	appTransport, err := ghinstallation.NewKeyFromFile(http.DefaultTransport, os.Getenv("GITHUB_CLIENT_ID"), installationID, os.Getenv("GITHUB_PEM_PATH"))
	if err != nil {
		return fmt.Errorf("github app transport: %w", err)
	}

	token, err := appTransport.Token(context.Background())
	if err != nil {
		return fmt.Errorf("github app token: %w", err)
	}
	_, _ = fmt.Fprint(os.Stdout, token)
	return nil
}
