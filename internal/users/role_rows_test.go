// @spec system-auth-identity

package users

import (
	"context"
	"errors"
	"testing"

	"github.com/Hanalyx/openwatch/internal/identity"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// streamErrRows yields no row and then reports that the stream failed,
// as when the connection breaks part way through a result.
type streamErrRows struct {
	pgx.Rows
	err error
}

func (r *streamErrRows) Next() bool { return false }
func (r *streamErrRows) Err() error { return r.err }
func (r *streamErrRows) Close()     {}

type streamErrQuerier struct{ err error }

func (q streamErrQuerier) Query(context.Context, string, ...any) (pgx.Rows, error) {
	return &streamErrRows{err: q.err}, nil
}

// @ac AC-92
// AC-92, at the role lookup: an error that ends the rows is a failed
// lookup, never an empty role list, so it cannot read as "no roles".
func TestRoleLookup_StreamErrorIsNotNoRoles(t *testing.T) {
	t.Run("system-auth-identity/AC-92", func(t *testing.T) {
		broken := errors.New("stream failed part way through")
		s := &Service{roleRows: streamErrQuerier{err: broken}}
		id := uuid.New()

		roles, err := s.RolesForUser(context.Background(), id)
		if !errors.Is(err, broken) {
			t.Errorf("RolesForUser = %v, %v; want the stream error", roles, err)
		}
		_, err = s.RoleForUser(context.Background(), id)
		if errors.Is(err, identity.ErrNoRoles) {
			t.Error("a failed stream was reported as the confirmed no-roles answer")
		}
		if err == nil {
			t.Error("a failed stream produced a role")
		}
	})
}
