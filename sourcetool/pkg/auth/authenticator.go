//go:generate go run github.com/maxbrunsfeld/counterfeiter/v6 -generate

package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/fatih/color"
	"github.com/google/go-github/v69/github"
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
	"repo", "user:email",
}

type Authenticator struct {
	impl authenticatorImplementation
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
		impl: &defaultImplementation{},
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
	return github.NewClient(nil).WithAuthToken(token), nil
}

// WhoAmI returns the user authenticated with the token
func (a *Authenticator) WhoAmI() (*github.User, error) {
	token, err := a.impl.readToken()
	if err != nil {
		return nil, fmt.Errorf("reading token: %w", err)
	}

	// If no token is set, then no error, only nil
	if token == "" {
		return nil, nil
	}

	client, err := a.GetGitHubClient()
	if err != nil {
		return nil, err
	}

	user, _, err := client.Users.Get(context.Background(), "")
	if err != nil {
		return nil, fmt.Errorf("fetching user data: %w", err)
	}

	return user, nil
}
