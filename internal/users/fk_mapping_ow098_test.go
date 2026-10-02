// @spec system-api-tokens
//
// AC-13 (users arm): only the role foreign key is reported as an unknown
// role. bugs/OW-098, where a granted_by that was not a user surfaced as
// 400 users.unknown_role for a role that exists. DSN-gated.
package users

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/Hanalyx/openwatch/internal/auth"
)

// @ac AC-13
func TestAssignRole_OnlyTheRoleKeyIsAnUnknownRole(t *testing.T) {
	t.Run("system-api-tokens/AC-13", func(t *testing.T) {
		svc, _ := freshService(t, nil)
		ctx := context.Background()
		u, err := svc.CreateUser(ctx, CreateParams{Username: "fkmap", Email: "fkmap@example.com", Password: strongPW()})
		if err != nil {
			t.Fatalf("create user: %v", err)
		}
		if err := svc.AssignRole(ctx, u.ID, auth.RoleID("no_such_role"), nil); !errors.Is(err, ErrUnknownRole) {
			t.Errorf("unknown role: err = %v, want ErrUnknownRole", err)
		}
		notAUser := uuid.New()
		err = svc.AssignRole(ctx, u.ID, auth.RoleViewer, &notAUser)
		if err == nil {
			t.Fatal("a granted_by that is not a user was accepted")
		}
		if errors.Is(err, ErrUnknownRole) {
			t.Errorf("a granted_by violation was reported as an unknown role: %v", err)
		}
	})
}
