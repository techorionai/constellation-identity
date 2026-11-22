package domain

import "time"

// TouchInterval is the shortest time between two writes of the last seen time
// of a session.
const TouchInterval = time.Minute

// Session is a browser session of a user.
type Session struct {
	ID        string
	UserID    string
	TokenHash string
	CreatedAt time.Time
	// AuthTime is the time of the last login of the session. A login of the same
	// user changes it. CreatedAt does not change.
	AuthTime      time.Time
	LastSeenAt    time.Time
	IdleExpiresAt time.Time
	ExpiresAt     time.Time
	RevokedAt     *time.Time
	UserAgent     string
	IPAddress     string
}

// SessionPolicy gives the life of a session.
type SessionPolicy struct {
	IdleTimeout     time.Duration
	AbsoluteTimeout time.Duration
}

// NewSession makes the session data for a user at the time now. The caller
// sets the ID and the token hash.
func (p SessionPolicy) NewSession(userID string, now time.Time) Session {
	return Session{
		UserID:        userID,
		CreatedAt:     now,
		AuthTime:      now,
		LastSeenAt:    now,
		IdleExpiresAt: now.Add(min(p.IdleTimeout, p.AbsoluteTimeout)),
		ExpiresAt:     now.Add(p.AbsoluteTimeout),
	}
}

// Valid reports whether the session is not revoked and has not expired.
func (s Session) Valid(now time.Time) bool {
	return s.RevokedAt == nil && now.Before(s.IdleExpiresAt) && now.Before(s.ExpiresAt)
}

// NeedsTouch reports whether the last seen time is old enough for a write.
func (s Session) NeedsTouch(now time.Time) bool {
	return now.Sub(s.LastSeenAt) >= TouchInterval
}

// IdleExpiry returns the new idle expiry for a touch at the time now. It does
// not pass the absolute expiry.
func (p SessionPolicy) IdleExpiry(s Session, now time.Time) time.Time {
	e := now.Add(p.IdleTimeout)
	if e.After(s.ExpiresAt) {
		return s.ExpiresAt
	}
	return e
}

// KeepOnRelogin reports whether a good login keeps the previous session. The
// previous session must be valid (not revoked and not expired) and must belong
// to the user that logs in.
func (s Session) KeepOnRelogin(userID string, now time.Time) bool {
	return s.UserID == userID && s.Valid(now)
}
