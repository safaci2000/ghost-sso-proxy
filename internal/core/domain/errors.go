package domain

import "errors"

// ErrUserNotFound is returned when no Ghost staff user matches the OIDC email.
var ErrUserNotFound = errors.New("ghost staff user not found")

// ErrUnauthorized is returned when the user exists but is not an active staff member.
var ErrUnauthorized = errors.New("user is not an active Ghost staff member")

// ErrNoToken is returned when no OIDC ID token cookie can be located in the request.
var ErrNoToken = errors.New("no OIDC identity token found in request cookies")

// ErrInvalidToken is returned when the token cannot be decoded or is malformed.
var ErrInvalidToken = errors.New("invalid or malformed OIDC token")
