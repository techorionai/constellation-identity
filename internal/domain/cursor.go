package domain

import "time"

// PageCursor is the position after the last item of a page. Lists of items
// with a creation time use CreatedAt and ID.
type PageCursor struct {
	CreatedAt time.Time
	ID        string
}
