// Package knownhosts is a PostgreSQL-backed ssh.KnownHostsStore. It makes
// host-key trust-on-first-use durable across process restarts: the first
// key seen for a hostname is persisted and verified on every later
// connection, so a network attacker can MITM at most the genuine first-ever
// connection to a host — not the first scan after each daemon restart, as
// the in-memory store allowed.
//
// It lives outside internal/ssh so the low-level dial layer stays free of a
// database dependency; it satisfies the ssh.KnownHostsStore interface.
package knownhosts

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Store implements ssh.KnownHostsStore against the ssh_known_hosts table.
type Store struct {
	pool *pgxpool.Pool
}

// NewStore returns a Postgres-backed known-hosts store.
func NewStore(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

// Get returns the stored marshalled public key for hostname, or
// (nil, false) when no row exists. Errors are treated as "not found" so a
// transient DB blip degrades to the TOFU first-seen path rather than failing
// closed (the dial layer still rejects a *mismatched* key on its own).
func (s *Store) Get(hostname string) ([]byte, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var key []byte
	err := s.pool.QueryRow(ctx,
		`SELECT public_key FROM ssh_known_hosts WHERE hostname = $1`, hostname).Scan(&key)
	if err != nil || len(key) == 0 {
		return nil, false
	}
	return key, true
}

// Put records the marshalled public key for hostname. It inserts on first
// sight and only refreshes last_seen when the key matches; the dial layer
// owns the mismatch policy (it calls Put only for a first-seen host), so a
// changed key is rejected upstream before Put is ever reached.
func (s *Store) Put(hostname string, marshalled []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := s.pool.Exec(ctx,
		`INSERT INTO ssh_known_hosts (hostname, public_key)
		 VALUES ($1, $2)
		 ON CONFLICT (hostname) DO UPDATE SET last_seen = now()
		 WHERE ssh_known_hosts.public_key = EXCLUDED.public_key`,
		hostname, marshalled)
	return err
}
