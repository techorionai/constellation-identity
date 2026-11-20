package queries

import (
	"context"
	"errors"
	"fmt"

	"github.com/techorionai/constellation-platform-go/executor"

	apperrors "github.com/techorionai/constellation-identity/internal/common/errors"
	"github.com/techorionai/constellation-identity/internal/domain"
	"github.com/techorionai/constellation-identity/internal/ports/manifests"
)

// ListManifests is the input of the manifest list.
type ListManifests struct {
	PageToken string
	PageSize  int
}

// ListManifestsResult is one page of manifests.
type ListManifestsResult struct {
	Items         []domain.PublishedManifest
	NextPageToken string
}

// ListManifestsQuery lists the manifests in app order.
type ListManifestsQuery struct{ repo manifests.Repository }

var _ executor.ExecutorWithReturn[ListManifests, ListManifestsResult] = (*ListManifestsQuery)(nil)

// NewListManifests makes the query.
func NewListManifests(repo manifests.Repository) *ListManifestsQuery {
	return &ListManifestsQuery{repo: repo}
}

// Execute returns one page.
func (q *ListManifestsQuery) Execute(ctx context.Context, in ListManifests) (ListManifestsResult, error) {
	size, err := pageSize(in.PageSize)
	if err != nil {
		return ListManifestsResult{}, err
	}
	cursor, err := decodePageToken(in.PageToken)
	if err != nil {
		return ListManifestsResult{}, err
	}
	if cursor != "" && !domain.ValidAppKey(cursor) {
		return ListManifestsResult{}, apperrors.NewInvalidInput("pageToken is not valid")
	}
	items, err := q.repo.List(ctx, cursor, size+1)
	if err != nil {
		return ListManifestsResult{}, fmt.Errorf("list manifests: %w", err)
	}
	res := ListManifestsResult{Items: items}
	if len(items) > size {
		res.Items = items[:size]
		res.NextPageToken = encodePageToken(items[size-1].Manifest.App)
	}
	return res, nil
}

// GetManifest is the input of the manifest read.
type GetManifest struct{ App string }

// GetManifestQuery reads the manifest of one app.
type GetManifestQuery struct{ repo manifests.Repository }

var _ executor.ExecutorWithReturn[GetManifest, domain.PublishedManifest] = (*GetManifestQuery)(nil)

// NewGetManifest makes the query.
func NewGetManifest(repo manifests.Repository) *GetManifestQuery {
	return &GetManifestQuery{repo: repo}
}

// Execute returns the manifest or a NotFound error.
func (q *GetManifestQuery) Execute(ctx context.Context, in GetManifest) (domain.PublishedManifest, error) {
	m, err := q.repo.Get(ctx, in.App)
	if errors.Is(err, manifests.ErrNotFound) {
		return domain.PublishedManifest{}, apperrors.NewNotFound("manifest not found")
	}
	if err != nil {
		return domain.PublishedManifest{}, fmt.Errorf("get manifest: %w", err)
	}
	return m, nil
}
