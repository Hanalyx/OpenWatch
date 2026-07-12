// @spec system-user-management
//
// Users + role-assignment tests covering all 12 ACs. Skipped without
// OPENWATCH_TEST_DSN.

package users

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/Hanalyx/openwatch/internal/auth"
	"github.com/Hanalyx/openwatch/internal/db/dbtest"
	"github.com/Hanalyx/openwatch/internal/identity"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// freshService returns a Service against a migrated, empty DB. Each
// test gets isolation via TRUNCATE users CASCADE; user_roles + sessions
// cascade off it.
func freshService(t *testing.T, corpus identity.BreachCorpus) (*Service, *pgxpool.Pool) {
	t.Helper()
	pool := dbtest.Pool(t)
	ctx := context.Background()
	_, _ = pool.Exec(ctx, "TRUNCATE TABLE users CASCADE")
	return NewService(pool, corpus), pool
}

// strongPW returns a long-enough, not-breached password for tests.
func strongPW() string { return "test-passphrase-strong-zZ" }

// @ac AC-14
// AC-14: UpdateProfile applies a PARTIAL self-profile edit (nil field
// unchanged, present field replaces), and treats email as the sign-in
// identity — unique among active users (ErrEmailTaken) and non-empty
// (ErrInvalidProfile).
func TestUpdateProfile_PartialAndEmailUniqueness(t *testing.T) {
	t.Run("system-user-management/AC-14", func(t *testing.T) {
		svc, _ := freshService(t, nil)
		ctx := context.Background()
		a, err := svc.CreateUser(ctx, CreateParams{Username: "alice", Email: "alice@example.com", Password: strongPW()})
		if err != nil {
			t.Fatalf("create alice: %v", err)
		}
		if _, err := svc.CreateUser(ctx, CreateParams{Username: "bob", Email: "bob@example.com", Password: strongPW()}); err != nil {
			t.Fatalf("create bob: %v", err)
		}

		// Partial: set full_name + timezone; email + others unchanged.
		fn, tz := "Alice Ann", "America/New_York"
		u, err := svc.UpdateProfile(ctx, a.ID, ProfileUpdate{FullName: &fn, Timezone: &tz})
		if err != nil {
			t.Fatalf("UpdateProfile: %v", err)
		}
		if u.FullName != fn || u.Timezone != tz {
			t.Errorf("fields not applied: %+v", u)
		}
		if u.Email != "alice@example.com" {
			t.Errorf("email changed unexpectedly to %q", u.Email)
		}
		if u.DisplayName != "" {
			t.Errorf("display_name should stay empty, got %q", u.DisplayName)
		}

		// Email change to an unused address succeeds.
		ne := "alice2@example.com"
		u, err = svc.UpdateProfile(ctx, a.ID, ProfileUpdate{Email: &ne})
		if err != nil {
			t.Fatalf("email change: %v", err)
		}
		if u.Email != ne {
			t.Errorf("email = %q, want %q", u.Email, ne)
		}

		// Collision with bob's email → ErrEmailTaken.
		taken := "bob@example.com"
		if _, err := svc.UpdateProfile(ctx, a.ID, ProfileUpdate{Email: &taken}); !errors.Is(err, ErrEmailTaken) {
			t.Errorf("expected ErrEmailTaken, got %v", err)
		}
		// Empty email → ErrInvalidProfile.
		empty := ""
		if _, err := svc.UpdateProfile(ctx, a.ID, ProfileUpdate{Email: &empty}); !errors.Is(err, ErrInvalidProfile) {
			t.Errorf("expected ErrInvalidProfile, got %v", err)
		}
	})
}

// @ac AC-01
// AC-01: CreateUser persists a row with Argon2id hash; returned User
// has NO PasswordHash field.
func TestCreateUser_PersistsAndNoHashLeak(t *testing.T) {
	t.Run("system-user-management/AC-01", func(t *testing.T) {
		svc, pool := freshService(t, nil)
		u, err := svc.CreateUser(context.Background(), CreateParams{
			Username: "ac01", Email: "ac01@example.com", Password: strongPW(),
		})
		if err != nil {
			t.Fatalf("CreateUser: %v", err)
		}
		// Returned struct: no PasswordHash field (reflect-checked so a
		// future refactor that accidentally exposes it would fail).
		typ := reflect.TypeOf(u)
		for i := 0; i < typ.NumField(); i++ {
			if typ.Field(i).Name == "PasswordHash" {
				t.Error("User struct exposes PasswordHash field — security violation per spec C-01")
			}
		}
		// DB row exists with non-empty hash.
		var hash string
		_ = pool.QueryRow(context.Background(),
			`SELECT password_hash FROM users WHERE id = $1`, u.ID).Scan(&hash)
		if hash == "" {
			t.Error("password_hash empty after CreateUser")
		}
		if hash == strongPW() {
			t.Error("password stored in plaintext — security violation")
		}
	})
}

// @ac AC-02
// AC-02: CreateUser surfaces identity.ValidatePassword errors unchanged.
func TestCreateUser_PolicyErrors(t *testing.T) {
	t.Run("system-user-management/AC-02", func(t *testing.T) {
		corpus := identity.NewMemoryBreachCorpus([]string{"password123"})
		svc, _ := freshService(t, corpus)
		// Too short.
		_, err := svc.CreateUser(context.Background(), CreateParams{
			Username: "short", Email: "s@example.com", Password: "abc",
		})
		if !errors.Is(err, identity.ErrPasswordTooShort) {
			t.Errorf("err = %v, want ErrPasswordTooShort", err)
		}
		// Breached.
		_, err = svc.CreateUser(context.Background(), CreateParams{
			Username: "breached", Email: "b@example.com", Password: "password123",
		})
		if !errors.Is(err, identity.ErrPasswordBreached) {
			t.Errorf("err = %v, want ErrPasswordBreached", err)
		}
	})
}

// @ac AC-03
// AC-03: AdminPolicy=true triggers the 15-char minimum; 14 chars rejected,
// 15 chars accepted. Replaces the legacy is_admin flag which has been
// removed from the table; callers now opt into AdminPolicy explicitly
// at creation time.
func TestCreateUser_AdminPolicy(t *testing.T) {
	t.Run("system-user-management/AC-03", func(t *testing.T) {
		svc, _ := freshService(t, nil)
		_, err := svc.CreateUser(context.Background(), CreateParams{
			Username: "admin14", Email: "a14@example.com",
			Password: "aaaaaaaaaaaaaa", AdminPolicy: true, // 14 chars
		})
		if !errors.Is(err, identity.ErrPasswordTooShort) {
			t.Errorf("14-char admin password err = %v, want ErrPasswordTooShort", err)
		}
		_, err = svc.CreateUser(context.Background(), CreateParams{
			Username: "admin15", Email: "a15@example.com",
			Password: "aaaaaaaaaaaaaaa", AdminPolicy: true, // 15 chars
		})
		if err != nil {
			t.Errorf("15-char admin password rejected: %v", err)
		}
	})
}

// @ac AC-04
// AC-04: GetUserByID returns user when active; ErrUserNotFound otherwise.
func TestGetUserByID(t *testing.T) {
	t.Run("system-user-management/AC-04", func(t *testing.T) {
		svc, _ := freshService(t, nil)
		u, err := svc.CreateUser(context.Background(), CreateParams{
			Username: "ac04", Email: "ac04@example.com", Password: strongPW(),
		})
		if err != nil {
			t.Fatalf("CreateUser: %v", err)
		}
		got, err := svc.GetUserByID(context.Background(), u.ID)
		if err != nil {
			t.Fatalf("GetUserByID: %v", err)
		}
		if got.Username != "ac04" {
			t.Errorf("Username = %q, want ac04", got.Username)
		}
		// Unknown ID → not found.
		unknown, _ := uuid.NewV7()
		_, err = svc.GetUserByID(context.Background(), unknown)
		if !errors.Is(err, ErrUserNotFound) {
			t.Errorf("unknown err = %v, want ErrUserNotFound", err)
		}
	})
}

// @ac AC-05
// AC-05: GetUserByUsername mirrors AC-04. Soft-deleted users invisible.
func TestGetUserByUsername_SoftDeleteHides(t *testing.T) {
	t.Run("system-user-management/AC-05", func(t *testing.T) {
		svc, _ := freshService(t, nil)
		u, err := svc.CreateUser(context.Background(), CreateParams{
			Username: "ac05", Email: "ac05@example.com", Password: strongPW(),
		})
		if err != nil {
			t.Fatalf("CreateUser: %v", err)
		}
		got, err := svc.GetUserByUsername(context.Background(), "ac05")
		if err != nil || got.ID != u.ID {
			t.Errorf("first lookup: err=%v id=%v", err, got.ID)
		}
		if err := svc.SoftDelete(context.Background(), u.ID); err != nil {
			t.Fatalf("SoftDelete: %v", err)
		}
		_, err = svc.GetUserByUsername(context.Background(), "ac05")
		if !errors.Is(err, ErrUserNotFound) {
			t.Errorf("after delete: err = %v, want ErrUserNotFound", err)
		}
	})
}

// @ac AC-06
// AC-06: UpdatePassword re-runs policy validation and bumps
// last_password_change_at on success.
func TestUpdatePassword(t *testing.T) {
	t.Run("system-user-management/AC-06", func(t *testing.T) {
		svc, _ := freshService(t, nil)
		u, err := svc.CreateUser(context.Background(), CreateParams{
			Username: "ac06", Email: "ac06@example.com", Password: strongPW(),
		})
		if err != nil {
			t.Fatalf("CreateUser: %v", err)
		}
		before := u.LastPasswordChangeAt

		// Too-short password rejected; timestamp NOT bumped.
		err = svc.UpdatePassword(context.Background(), u.ID, "abc")
		if !errors.Is(err, identity.ErrPasswordTooShort) {
			t.Errorf("short password err = %v, want ErrPasswordTooShort", err)
		}
		// Valid update succeeds; verify password works against new value.
		newPW := "new-passphrase-strong-zZ"
		if err := svc.UpdatePassword(context.Background(), u.ID, newPW); err != nil {
			t.Fatalf("UpdatePassword: %v", err)
		}
		got, _ := svc.GetUserByID(context.Background(), u.ID)
		if !got.LastPasswordChangeAt.After(before) {
			t.Errorf("last_password_change_at not bumped (before=%v, after=%v)", before, got.LastPasswordChangeAt)
		}
		if _, err := svc.VerifyUserPassword(context.Background(), "ac06", newPW); err != nil {
			t.Errorf("verify new password: %v", err)
		}
		if _, err := svc.VerifyUserPassword(context.Background(), "ac06", strongPW()); err == nil {
			t.Error("verify old password still works — update did not take effect")
		}
	})
}

// @ac AC-07
// AC-07: SoftDelete makes the row invisible to lookups; username can
// be reused per the migration's partial unique index.
func TestSoftDeleteAllowsReuse(t *testing.T) {
	t.Run("system-user-management/AC-07", func(t *testing.T) {
		svc, _ := freshService(t, nil)
		u, err := svc.CreateUser(context.Background(), CreateParams{
			Username: "reusable", Email: "reusable@example.com", Password: strongPW(),
		})
		if err != nil {
			t.Fatalf("CreateUser: %v", err)
		}
		if err := svc.SoftDelete(context.Background(), u.ID); err != nil {
			t.Fatalf("SoftDelete: %v", err)
		}
		// Re-create with the same username — partial unique index allows it.
		_, err = svc.CreateUser(context.Background(), CreateParams{
			Username: "reusable", Email: "reusable@example.com", Password: strongPW(),
		})
		if err != nil {
			t.Errorf("re-create with reused username: %v", err)
		}
	})
}

// @ac AC-08
// AC-08: AssignRole inserts row for valid role; ErrUnknownRole for
// unregistered ids.
func TestAssignRole(t *testing.T) {
	t.Run("system-user-management/AC-08", func(t *testing.T) {
		svc, pool := freshService(t, nil)
		u, err := svc.CreateUser(context.Background(), CreateParams{
			Username: "ac08", Email: "ac08@example.com", Password: strongPW(),
		})
		if err != nil {
			t.Fatalf("CreateUser: %v", err)
		}
		if err := svc.AssignRole(context.Background(), u.ID, auth.RoleViewer, nil); err != nil {
			t.Fatalf("AssignRole viewer: %v", err)
		}
		var count int64
		_ = pool.QueryRow(context.Background(),
			`SELECT count(*) FROM user_roles WHERE user_id = $1 AND role_id = 'viewer'`, u.ID,
		).Scan(&count)
		if count != 1 {
			t.Errorf("user_roles count = %d, want 1", count)
		}
		// Unknown role.
		err = svc.AssignRole(context.Background(), u.ID, auth.RoleID("not_a_role"), nil)
		if !errors.Is(err, ErrUnknownRole) {
			t.Errorf("unknown role err = %v, want ErrUnknownRole", err)
		}
	})
}

// @ac AC-09
// AC-09: RolesForUser returns assignments; soft-deleted user returns
// empty (not error).
func TestRolesForUser(t *testing.T) {
	t.Run("system-user-management/AC-09", func(t *testing.T) {
		svc, _ := freshService(t, nil)
		u, _ := svc.CreateUser(context.Background(), CreateParams{
			Username: "ac09", Email: "ac09@example.com", Password: strongPW(),
		})
		_ = svc.AssignRole(context.Background(), u.ID, auth.RoleViewer, nil)
		_ = svc.AssignRole(context.Background(), u.ID, auth.RoleOpsLead, nil)

		roles, err := svc.RolesForUser(context.Background(), u.ID)
		if err != nil {
			t.Fatalf("RolesForUser: %v", err)
		}
		seen := map[auth.RoleID]bool{}
		for _, r := range roles {
			seen[r] = true
		}
		if !seen[auth.RoleViewer] || !seen[auth.RoleOpsLead] {
			t.Errorf("RolesForUser = %v, want both viewer and ops_lead", roles)
		}
		// Soft-delete → empty.
		_ = svc.SoftDelete(context.Background(), u.ID)
		roles, err = svc.RolesForUser(context.Background(), u.ID)
		if err != nil {
			t.Fatalf("RolesForUser after delete: %v", err)
		}
		if len(roles) != 0 {
			t.Errorf("after delete RolesForUser = %v, want empty", roles)
		}
	})
}

// @ac AC-10
// AC-10: UnassignRole removes the link; idempotent.
func TestUnassignRole_Idempotent(t *testing.T) {
	t.Run("system-user-management/AC-10", func(t *testing.T) {
		svc, _ := freshService(t, nil)
		u, _ := svc.CreateUser(context.Background(), CreateParams{
			Username: "ac10", Email: "ac10@example.com", Password: strongPW(),
		})
		_ = svc.AssignRole(context.Background(), u.ID, auth.RoleViewer, nil)
		if err := svc.UnassignRole(context.Background(), u.ID, auth.RoleViewer); err != nil {
			t.Errorf("UnassignRole: %v", err)
		}
		// Second call: no error.
		if err := svc.UnassignRole(context.Background(), u.ID, auth.RoleViewer); err != nil {
			t.Errorf("second UnassignRole: %v", err)
		}
	})
}

// @ac AC-11
// AC-11: PrimaryRoleFor returns highest-precedence role.
func TestPrimaryRoleFor(t *testing.T) {
	t.Run("system-user-management/AC-11", func(t *testing.T) {
		svc, _ := freshService(t, nil)
		u, _ := svc.CreateUser(context.Background(), CreateParams{
			Username: "ac11", Email: "ac11@example.com", Password: strongPW(),
		})
		_ = svc.AssignRole(context.Background(), u.ID, auth.RoleViewer, nil)
		_ = svc.AssignRole(context.Background(), u.ID, auth.RoleOpsLead, nil)
		got, err := svc.PrimaryRoleFor(context.Background(), u.ID)
		if err != nil {
			t.Fatalf("PrimaryRoleFor: %v", err)
		}
		if got != auth.RoleOpsLead {
			t.Errorf("primary = %q, want ops_lead", got)
		}
		// Promote to admin — that's the new primary.
		_ = svc.AssignRole(context.Background(), u.ID, auth.RoleAdmin, nil)
		got, _ = svc.PrimaryRoleFor(context.Background(), u.ID)
		if got != auth.RoleAdmin {
			t.Errorf("primary after admin = %q, want admin", got)
		}
		// No roles → error.
		u2, _ := svc.CreateUser(context.Background(), CreateParams{
			Username: "noroles", Email: "n@example.com", Password: strongPW(),
		})
		_, err = svc.PrimaryRoleFor(context.Background(), u2.ID)
		if !errors.Is(err, ErrUserHasNoRoles) {
			t.Errorf("no-roles err = %v, want ErrUserHasNoRoles", err)
		}
	})
}

// @ac AC-12
// AC-12: Migration seeds the 5 built-in roles; AssignRole works without
// any post-migrate setup.
func TestBuiltInRolesSeeded(t *testing.T) {
	t.Run("system-user-management/AC-12", func(t *testing.T) {
		svc, pool := freshService(t, nil)
		var count int64
		_ = pool.QueryRow(context.Background(),
			`SELECT count(*) FROM roles WHERE is_built_in = true`,
		).Scan(&count)
		if count != 5 {
			t.Errorf("built-in roles seeded = %d, want 5", count)
		}
		// AssignRole works without any extra setup.
		u, _ := svc.CreateUser(context.Background(), CreateParams{
			Username: "ac12", Email: "ac12@example.com", Password: strongPW(),
		})
		for _, r := range []auth.RoleID{
			auth.RoleViewer, auth.RoleAuditor, auth.RoleOpsLead,
			auth.RoleSecurityAdmin, auth.RoleAdmin,
		} {
			if err := svc.AssignRole(context.Background(), u.ID, r, nil); err != nil {
				t.Errorf("AssignRole %q: %v", r, err)
			}
		}
	})
}

// @ac AC-13
// AC-13: ListUsers aggregates each user's role ids into User.Roles
// (non-nil empty slice when none); soft-deleted users are excluded.
func TestListUsers_PopulatesRoles(t *testing.T) {
	t.Run("system-user-management/AC-13", func(t *testing.T) {
		svc, _ := freshService(t, nil)
		ctx := context.Background()
		withRoles, _ := svc.CreateUser(ctx, CreateParams{
			Username: "ac13roles", Email: "ac13roles@example.com", Password: strongPW(),
		})
		_ = svc.AssignRole(ctx, withRoles.ID, auth.RoleViewer, nil)
		_ = svc.AssignRole(ctx, withRoles.ID, auth.RoleOpsLead, nil)
		none, _ := svc.CreateUser(ctx, CreateParams{
			Username: "ac13none", Email: "ac13none@example.com", Password: strongPW(),
		})
		gone, _ := svc.CreateUser(ctx, CreateParams{
			Username: "ac13gone", Email: "ac13gone@example.com", Password: strongPW(),
		})
		_ = svc.SoftDelete(ctx, gone.ID)

		list, err := svc.ListUsers(ctx)
		if err != nil {
			t.Fatalf("ListUsers: %v", err)
		}
		byID := map[uuid.UUID]User{}
		for _, u := range list {
			byID[u.ID] = u
		}
		if _, ok := byID[gone.ID]; ok {
			t.Error("soft-deleted user appeared in ListUsers")
		}
		// The no-role user lists with a non-nil empty Roles slice.
		nu, ok := byID[none.ID]
		if !ok {
			t.Fatal("no-role user missing from ListUsers")
		}
		if nu.Roles == nil || len(nu.Roles) != 0 {
			t.Errorf("no-role user Roles = %v, want non-nil empty slice", nu.Roles)
		}
		// The two-role user lists both ids (subquery orders them).
		ru, ok := byID[withRoles.ID]
		if !ok {
			t.Fatal("roled user missing from ListUsers")
		}
		seen := map[string]bool{}
		for _, r := range ru.Roles {
			seen[r] = true
		}
		if !seen[string(auth.RoleViewer)] || !seen[string(auth.RoleOpsLead)] {
			t.Errorf("roled user Roles = %v, want viewer + ops_lead", ru.Roles)
		}
	})
}

// @spec system-sso
// @ac AC-08
// CreateFederatedUser provisions a passwordless SSO user with a role, and a
// username/email collision surfaces as an error (no silent merge).
func TestCreateFederatedUser(t *testing.T) {
	t.Run("system-sso/AC-08", func(t *testing.T) {
		svc, pool := freshService(t, nil)
		ctx := context.Background()
		u, err := svc.CreateFederatedUser(ctx, "fed@example.com", "fed@example.com", auth.RoleViewer)
		if err != nil {
			t.Fatalf("CreateFederatedUser: %v", err)
		}
		// Default role assigned.
		var n int
		_ = pool.QueryRow(ctx,
			`SELECT count(*) FROM user_roles WHERE user_id = $1 AND role_id = 'viewer'`, u.ID).Scan(&n)
		if n != 1 {
			t.Errorf("role count = %d, want 1", n)
		}
		// A password hash exists (random + unusable) — never empty.
		var hash string
		_ = pool.QueryRow(ctx, `SELECT password_hash FROM users WHERE id = $1`, u.ID).Scan(&hash)
		if hash == "" {
			t.Error("federated user has empty password_hash")
		}
		// Username collision is an error, not a silent merge.
		if _, err := svc.CreateFederatedUser(ctx, "fed@example.com", "fed@example.com", auth.RoleViewer); err == nil {
			t.Error("duplicate federated provisioning succeeded, want error")
		}
	})
}
