// Package ghostapi implements the driven.UserRepository port using the Ghost
// Admin API. All requests are authenticated with a short-lived HS256 JWT
// derived from a Ghost Admin API key (format: "<id>:<hex-secret>").
package ghostapi

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/safaci2000/ghost-sso-proxy/internal/core/domain"
)

// UserRepository implements driven.UserRepository via the Ghost Admin API.
type UserRepository struct {
	adminURL string
	keyID    string
	secret   []byte
	client   *http.Client
}

// NewUserRepository parses the Ghost Admin API key and constructs a UserRepository.
// apiKey must be in Ghost's "<id>:<hex-encoded-secret>" format.
func NewUserRepository(adminURL, apiKey string) (*UserRepository, error) {
	parts := strings.SplitN(apiKey, ":", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return nil, fmt.Errorf("ghostapi: invalid Admin API key format — expected \"<id>:<hex-secret>\"")
	}
	secret, err := hex.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("ghostapi: decoding Admin API key secret: %w", err)
	}
	return &UserRepository{
		adminURL: strings.TrimRight(adminURL, "/"),
		keyID:    parts[0],
		secret:   secret,
		client:   &http.Client{Timeout: 10 * time.Second},
	}, nil
}

// ghostUsersResponse mirrors the Ghost Admin API /users/ response envelope.
type ghostUsersResponse struct {
	Users []struct {
		ID     string `json:"id"`
		Email  string `json:"email"`
		Status string `json:"status"`
	} `json:"users"`
}

// FindByEmail implements driven.UserRepository.
// It calls GET /ghost/api/admin/users/?filter=email:'<email>'&fields=id,email,status
// and returns the first matching user or domain.ErrUserNotFound.
func (r *UserRepository) FindByEmail(ctx context.Context, email string) (*domain.User, error) {
	token, err := r.signedJWT()
	if err != nil {
		return nil, fmt.Errorf("ghostapi: generating JWT: %w", err)
	}

	// Ghost NQL filter syntax: email:'user@example.com'
	filter := fmt.Sprintf("email:'%s'", email)
	reqURL := fmt.Sprintf("%s/ghost/api/admin/users/?filter=%s&fields=id,email,status",
		r.adminURL, url.QueryEscape(filter))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("ghostapi: building request: %w", err)
	}
	req.Header.Set("Authorization", "Ghost "+token)
	req.Header.Set("Accept-Version", "v5.0")

	resp, err := r.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ghostapi: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ghostapi: unexpected status %d", resp.StatusCode)
	}

	var result ghostUsersResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("ghostapi: decoding response: %w", err)
	}
	if len(result.Users) == 0 {
		return nil, domain.ErrUserNotFound
	}

	u := result.Users[0]
	return &domain.User{
		ID:     u.ID,
		Email:  u.Email,
		Status: u.Status,
	}, nil
}

// signedJWT produces a short-lived HS256 JWT for the Ghost Admin API.
// Ghost requires the "kid" header to contain the key ID, "aud" to be "/admin/",
// and the token to expire within 5 minutes of issuance.
func (r *UserRepository) signedJWT() (string, error) {
	now := time.Now()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"aud": "/admin/",
		"iat": now.Unix(),
		"exp": now.Add(5 * time.Minute).Unix(),
	})
	token.Header["kid"] = r.keyID

	signed, err := token.SignedString(r.secret)
	if err != nil {
		return "", fmt.Errorf("signing Ghost Admin API JWT: %w", err)
	}
	return signed, nil
}
