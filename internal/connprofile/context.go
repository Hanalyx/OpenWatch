package connprofile

import (
	"context"

	"github.com/google/uuid"
)

type hostIDKey struct{}

// WithHostID stashes the host id on ctx so a lower layer that only receives
// host:port + credential (e.g. an SSH transport behind an interface that
// can't easily grow a hostID parameter) can still look up and record this
// host's connection profile.
//
// This is best-effort learning enrichment, not a required dial parameter:
// a connection with no host id on the context simply skips the profile
// lookup/record and dials in the default order.
func WithHostID(ctx context.Context, id uuid.UUID) context.Context {
	return context.WithValue(ctx, hostIDKey{}, id)
}

// HostIDFrom returns the host id stashed by WithHostID. The bool is false
// when no (or a nil) id is present, so callers can guard the learning path.
func HostIDFrom(ctx context.Context) (uuid.UUID, bool) {
	id, ok := ctx.Value(hostIDKey{}).(uuid.UUID)
	return id, ok && id != uuid.Nil
}
