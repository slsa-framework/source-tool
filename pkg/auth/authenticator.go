// SPDX-FileCopyrightText: Copyright 2025 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

//go:generate go run github.com/maxbrunsfeld/counterfeiter/v6 -generate

package auth

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/google/go-github/v88/github"
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

	// githubActionsLogin is the identity reported when sourcetool is
	// authenticated using the GitHub Actions token (which acts on behalf of
	// the github-actions bot instead of a user).
	githubActionsLogin = "github-actions[bot]"
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
	client, err := github.NewClient(github.WithHTTPClient(httpClient), github.WithAuthToken(token))
	if err != nil {
		return nil, fmt.Errorf("creating github client: %w", err)
	}
	return client, nil
}

// WhoAmI returns the user authenticated with the token
func (a *Authenticator) WhoAmI() (*models.Actor, error) {
	token, err := a.impl.readToken()
	if err != nil {
		return nil, fmt.Errorf("reading token: %w", err)
	}

	cacheKey := fmt.Sprintf("%x", sha256.Sum256([]byte(token)))

	// Check the cache to avoid requesting again
	if user, ok := a.idCache[cacheKey]; ok {
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

	ctx := context.Background()

	// If we are on actions and the token is read from env, don't even try the
	// user authentication path.
	if os.Getenv("GITHUB_ACTIONS") != "" && os.Getenv("GITHUB_TOKEN") != "" && strings.Contains(os.Getenv("GITHUB_TOKEN"), token) {
		return a.whoAmIActions(ctx, client, cacheKey)
	}

	// Get the user from the GitHub API
	user, resp, err := client.Users.Get(ctx, "")
	if err != nil {
		// The GitHub Actions token (and other GitHub App installation tokens)
		// cannot read the /user endpoint. GitHub returns a 403 in that case
		// ("Resource not accessible by integration"). If we hit a 403, check
		// if the token can still be used by sourcetool by checking it against
		// as an actions/installation token (not a pat).
		if resp != nil && resp.StatusCode == http.StatusForbidden {
			return a.whoAmIActions(ctx, client, cacheKey)
		}
		return nil, fmt.Errorf("fetching user data: %w", err)
	}

	actor := &models.Actor{
		Login: user.GetLogin(),
	}
	a.idCache[cacheKey] = actor
	return actor, nil
}

// whoAmIActions verifies that an actions/installation token can be used
// by sourcetool. Instead of hitting the user endpoiint, we confirm it has
// access to the repository where workflow is running.
// On success it returns an agent synthesized from the github-actions bot
// identity.
func (a *Authenticator) whoAmIActions(ctx context.Context, client *github.Client, cacheKey string) (*models.Actor, error) {
	slug := os.Getenv("GITHUB_REPOSITORY")
	if slug == "" {
		return nil, errors.New(
			"unable to verify access to the repo (and token cannot access the user endpoint)",
		)
	}

	owner, repo, ok := strings.Cut(slug, "/")
	if !ok || owner == "" || repo == "" {
		return nil, fmt.Errorf("invalid GITHUB_REPOSITORY value %q", slug)
	}

	// Confirm the token actually grants access to the repository.
	if _, _, err := client.Repositories.Get(ctx, owner, repo); err != nil {
		return nil, fmt.Errorf("verifying actions token access to %s: %w", slug, err)
	}

	actor := &models.Actor{
		Login: githubActionsLogin,
	}
	a.idCache[cacheKey] = actor
	return actor, nil
}
