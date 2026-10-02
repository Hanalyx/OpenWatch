// @spec system-api-tokens
//
// AC-13 (SSO arm): only the default_role foreign key is a caller's invalid
// input. bugs/OW-098, where any insert failure answered 400 sso.invalid.
// DSN-gated.
package sso

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
)

// @ac AC-13
func TestCreate_OnlyTheRoleKeyIsInvalidParams(t *testing.T) {
	t.Run("system-api-tokens/AC-13", func(t *testing.T) {
		svc, _, d := freshSSO(t)
		ctx := context.Background()
		base := CreateParams{Name: "fk-a", Issuer: d.URL, ClientID: d.clientID, ClientSecret: "s", DefaultRole: "no_such_role", Enabled: true}
		if _, err := svc.Create(ctx, base); !errors.Is(err, ErrInvalidParams) {
			t.Errorf("unknown default_role: err = %v, want ErrInvalidParams", err)
		}
		notAUser := uuid.New()
		p := base
		p.Name, p.DefaultRole, p.CreatedBy = "fk-b", "viewer", &notAUser
		_, err := svc.Create(ctx, p)
		if err == nil {
			t.Fatal("a created_by that is not a user was accepted")
		}
		if errors.Is(err, ErrInvalidParams) {
			t.Errorf("a created_by violation was reported as invalid parameters: %v", err)
		}
	})
}
