// SPDX-FileCopyrightText: Copyright 2025 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

//go:generate go run github.com/maxbrunsfeld/counterfeiter/v6 -generate

package auth

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"github.com/fatih/color"
	"github.com/google/go-github/v69/github"
	"github.com/hashicorp/go-retryablehttp"

	"github.com/slsa-framework/source-tool/pkg/sourcetool/models"
)

const (
	// GitHub endpoints
	deviceCodeURL = "https://github.com/login/device/code"
	tokenURL      = "https://github.com/login/oauth/access_token" //nolint:gosec // not a credential

	// The SLSA sourcetool app OAuth client ID
	oauthClientID = "Ov23lidVQsiU5R5tod3z"

	// App's config directory name
	configDirName = "slsa"

	// Token filename
	githubTokenFileName = "sourcetool.github.token"
)

var oauthScopes = []string{
	"repo", "user:email", "workflow",
}

type Authenticator struct {
	impl    authenticatorImplementation
	idCache map[string]*models.Actor
}

// DeviceCodeResponse models the github device code response
type DeviceCodeResponse struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
}

// TokenResponse is the data structure returned when exchanging tokens
type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	Scope       string `json:"scope"`
	Error       string `json:"error"`
	ErrorDesc   string `json:"error_description"`
}

// NewGitHubApp creates a new GitHub OAuth application for device flow
func New() *Authenticator {
	return &Authenticator{
		impl:    &defaultImplementation{},
		idCache: map[string]*models.Actor{},
	}
}

// Authenticate performs the complete device flow authentication in the
// user's terminal and web browser
func (a *Authenticator) Authenticate(ctx context.Context) error {
	fmt.Println("Starting authentication flow...")

	// Get a device code
	deviceResp, err := a.impl.requestDeviceCode(ctx)
	if err != nil {
		return fmt.Errorf("failed to request device code: %w", err)
	}

	// Send the user to the authentication page
	fmt.Printf("\nYour browser will be opened to: %s\n\n", deviceResp.VerificationURI)
	fmt.Printf("   🔑 Enter this code: %s\n\n", color.New(color.FgHiWhite, color.BgBlack).Sprint(deviceResp.UserCode))

	// Try to open browser automatically
	if err := a.impl.openBrowser(deviceResp.VerificationURI); err != nil {
		fmt.Println("Failed to open browser, please manually visit the URL above.")
		fmt.Println()
	} else {
		fmt.Println("Please complete the authentication flow by pasting the above code in")
		fmt.Println("the page displayed on your browser.")
	}
	fmt.Println()

	fmt.Println("⏳ Waiting for authentication...")

	pollInterval := 5 * time.Second
	if deviceResp.Interval > 0 {
		pollInterval = time.Duration(deviceResp.Interval) * time.Second
	}

	// Wait for the user to complete the flow while polling the server to
	// get the newly issued token
	token, err := a.impl.pollForToken(ctx, deviceResp.DeviceCode, pollInterval)
	if err != nil {
		return fmt.Errorf("failed to get access token: %w", err)
	}

	fmt.Println("✅ Authentication successful!")
	fmt.Println()
	fmt.Println("At any point, you can find out the logged-in identity by running:")
	fmt.Println("> sourcetool auth whoami")
	fmt.Println()

	// Persist the token to disk
	return a.impl.persistToken(token)
}

// ReadToken reads the persisted token and returns it
func (a *Authenticator) ReadToken() (string, error) {
	return a.impl.readToken()
}

// GetGitHubClient returns a GitHub client preconfigured with
// the logged-in token.
func (a *Authenticator) GetGitHubClient() (*github.Client, error) {
	token, err := a.impl.readToken()
	if err != nil {
		return nil, fmt.Errorf("reading token: %w", err)
	}
	if token == "" {
		return nil, errors.New("token is empty")
	}

	rClient := retryablehttp.NewClient()
	rClient.RetryMax = 3
	rClient.Logger = nil // Comment this line to monitor GH api calls
	httpClient := rClient.StandardClient()
	return github.NewClient(httpClient).WithAuthToken(token), nil
}

// WhoAmI returns the user authenticated with the token
func (a *Authenticator) WhoAmI() (*models.Actor, error) {
	token, err := a.impl.readToken()
	if err != nil {
		return nil, fmt.Errorf("reading token: %w", err)
	}

	// Check the cache to avoid requesting again
	if user, ok := a.idCache[fmt.Sprintf("%x", sha256.Sum256([]byte(token)))]; ok {
		return user, nil
	}

	// If no token is set, then no error, only nil
	if token == "" {
		return nil, nil
	}

	client, err := a.GetGitHubClient()
	if err != nil {
		return nil, err
	}

	// Get the user from the GitHub API
	user, _, err := client.Users.Get(context.Background(), "")
	if err != nil {
		return nil, fmt.Errorf("fetching user data: %w", err)
	}

	return &models.Actor{
		Login: user.GetLogin(),
	}, nil
}
