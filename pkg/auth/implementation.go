// SPDX-FileCopyrightText: Copyright 2025 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

//counterfeiter:generate . authenticatorImplementation
type authenticatorImplementation interface {
	requestDeviceCode(context.Context) (*DeviceCodeResponse, error)
	openBrowser(string) error
	pollForToken(context.Context, string, time.Duration) (string, error)
	checkTokenStatus(context.Context, string) (string, error)
	persistToken(token string) error
	readToken() (string, error)
}

type defaultImplementation struct{}

// pollForToken polls GitHub periodically until the device flow is done and
// the token is issued.
func (di *defaultImplementation) pollForToken(ctx context.Context, deviceCode string, interval time.Duration) (string, error) {
	for {
		token, err := di.checkTokenStatus(ctx, deviceCode)
		if err != nil {
			if strings.Contains(err.Error(), "authorization_pending") {
				time.Sleep(interval)
				continue
			}
			if strings.Contains(err.Error(), "slow_down") {
				interval += 5 * time.Second
				time.Sleep(interval)
				continue
			}
			return "", err
		}
		return token, nil
	}
}

// checkTokenStatus checks if the device flow authorization is done and returns
// the token if ready.
func (di *defaultImplementation) checkTokenStatus(ctx context.Context, deviceCode string) (string, error) {
	data := url.Values{}
	data.Set("client_id", oauthClientID)
	data.Set("device_code", deviceCode)
	data.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return "", fmt.Errorf("failed to create token request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	httpClient := &http.Client{}
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to check token status: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read token response: %w", err)
	}

	var tokenResp TokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return "", fmt.Errorf("failed to parse token response: %w", err)
	}

	if tokenResp.Error != "" {
		return "", fmt.Errorf("got an API error checking token :%s", tokenResp.Error)
	}

	if tokenResp.AccessToken == "" {
		return "", fmt.Errorf("no access token received")
	}

	return tokenResp.AccessToken, nil
}

// openBrowser shells out to open the system's browser to load the
// device authorization webpage.
func (di *defaultImplementation) openBrowser(authURL string) error {
	var cmd string
	var args []string

	switch runtime.GOOS {
	case "windows":
		cmd = "cmd"
		args = []string{"/c", "start"}
	case "darwin":
		cmd = "open"
	default:
		cmd = "xdg-open"
	}

	return exec.CommandContext(context.Background(), cmd, append(args, authURL)...).Start() //nolint:gosec // yes variable input
}

// requestDeviceCode requests a device code from GitHub
func (di *defaultImplementation) requestDeviceCode(ctx context.Context) (*DeviceCodeResponse, error) {
	data := url.Values{}
	data.Set("client_id", oauthClientID)
	data.Set("scope", strings.Join(oauthScopes, " "))

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, deviceCodeURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create device code request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	httpClient := &http.Client{Timeout: 30 * time.Second}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to request device code: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("device code request failed with status: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading device code response: %w", err)
	}

	var deviceResp DeviceCodeResponse
	if err := json.Unmarshal(body, &deviceResp); err != nil {
		return nil, fmt.Errorf("parsing device code response: %w", err)
	}

	return &deviceResp, nil
}

// persistToken stores the token into the system config directory
func (di *defaultImplementation) persistToken(token string) error {
	dir, err := os.UserConfigDir()
	if err != nil {
		return fmt.Errorf("getting user config dir: %w", err)
	}

	if err := os.MkdirAll(filepath.Join(dir, configDirName), os.FileMode(0o700)); err != nil {
		return fmt.Errorf("creating config directory: %w", err)
	}

	err = os.WriteFile(filepath.Join(dir, configDirName, githubTokenFileName), []byte(token), os.FileMode(0o600))
	if err != nil {
		return fmt.Errorf("saving token file: %w", err)
	}
	return nil
}

func (di *defaultImplementation) readToken() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("getting user config dir: %w", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, configDirName, githubTokenFileName))
	if err != nil {
		// If the token file is not found, try reading it from the environment
		if errors.Is(err, os.ErrNotExist) {
			return os.Getenv("GITHUB_TOKEN"), nil
		}
		return "", fmt.Errorf("reading token file: %w", err)
	}

	ret := strings.TrimSpace(string(data))
	if ret == "" {
		return "", fmt.Errorf("token file is empty")
	}

	return ret, nil
}
