package domain

// User represents a Ghost staff member retrieved from the Admin API.
type User struct {
	// ID is Ghost's 24-character hex ObjectId for this staff member.
	ID string
	// Email is the user's email address, matched against the OIDC identity.
	Email string
	// Status is the Ghost account status, e.g. "active", "inactive", "suspended".
	Status string
}

// IsActive returns true when the user account is active and may log in.
func (u *User) IsActive() bool {
	return u.Status == "active"
}
