// @spec api-groups
//
// Service-level validation coverage for Create. These cases exercise the
// input-validation guards that return BEFORE any database access, so they
// run against a nil pool: reaching the DB would panic, which proves the
// guard short-circuited. The happy path and rollup queries are DB-backed
// and covered by integration tests elsewhere.
//
//	AC-01  TestCreate_ValidationShortCircuits
package group

import (
	"context"
	"errors"
	"testing"
)

// @ac AC-01
// Create rejects bad input before touching the pool. Each case is built to
// trip exactly one guard without satisfying an earlier one, and runs with a
// nil pool so any DB access would panic instead of returning the sentinel.
func TestCreate_ValidationShortCircuits(t *testing.T) {
	t.Run("api-groups/AC-01", func(t *testing.T) {
		// svc has a nil pool: a passing test proves Create returned before
		// s.pool.QueryRow was reached.
		svc := NewService(nil)
		ctx := context.Background()

		cases := []struct {
			name string
			in   CreateInput
			want error
		}{
			{
				name: "empty name",
				in:   CreateInput{Name: "", Kind: KindSite, Membership: MembershipManual},
				want: ErrEmptyName,
			},
			{
				name: "invalid kind",
				in:   CreateInput{Name: "g", Kind: Kind("bogus"), Membership: MembershipManual},
				want: ErrInvalidKind,
			},
			{
				name: "invalid membership",
				in:   CreateInput{Name: "g", Kind: KindOSCategory, Membership: Membership("bogus")},
				want: ErrInvalidMembership,
			},
			{
				name: "site must be manual",
				in:   CreateInput{Name: "g", Kind: KindSite, Membership: MembershipAuto, MatchFamily: "rhel"},
				want: ErrSiteMustBeManual,
			},
			{
				name: "auto needs family",
				in:   CreateInput{Name: "g", Kind: KindOSCategory, Membership: MembershipAuto, MatchFamily: ""},
				want: ErrAutoNeedsFamily,
			},
			{
				name: "manual must not set family",
				in:   CreateInput{Name: "g", Kind: KindOSCategory, Membership: MembershipManual, MatchFamily: "rhel"},
				want: ErrManualHasFamily,
			},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				got, err := svc.Create(ctx, tc.in)
				if !errors.Is(err, tc.want) {
					t.Fatalf("Create(%+v) err = %v, want %v", tc.in, err, tc.want)
				}
				if got != (Group{}) {
					t.Errorf("Create returned non-zero group on error: %+v", got)
				}
			})
		}
	})
}
