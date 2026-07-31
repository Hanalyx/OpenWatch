// @spec system-setup
//
//	AC-01  TestDSN_PasswordRoundTripsWhateverItContains
//	AC-02  TestPlan_DeriveComputesDependentFields
//	AC-03  TestPlan_ValidateRejectsUnsafeCombinations, TestPlan_DefaultIsValid
package setup

import (
	"net/url"
	"testing"
)

// The guarantee the whole design rests on: the operator types a raw password
// and never thinks about URI encoding, because the DSN is assembled by code
// that encodes correctly.
//
// This is not hypothetical. A v0.7.0 install failed exactly here: the guide had
// the operator paste a password containing '@' straight into a DSN template,
// net/url split the URI at the wrong '@', and the resulting authentication
// failure named the database role. Nothing pointed at the connection string.
// @ac AC-01
func TestDSN_PasswordRoundTripsWhateverItContains(t *testing.T) {
	t.Run("system-setup/AC-01", func(t *testing.T) {
		d := DatabasePlan{
			Host: "127.0.0.1", Port: 5432, Name: "openwatch",
			RoleName: "openwatch", SSLMode: "disable",
		}
		passwords := []string{
			"WindoW2005@@", // the real one, two trailing at-signs
			"p@ss@word",
			"a/b?c#d",
			"colon:pass",
			"percent%40literal", // must NOT be double-decoded
			"[brackets]",
			"sp ace",
			"simple",
		}
		for _, pw := range passwords {
			dsn := d.DSN(pw)
			u, err := url.Parse(dsn)
			if err != nil {
				t.Errorf("password %q produced an unparseable DSN: %v", pw, err)
				continue
			}
			got, set := u.User.Password()
			if !set || got != pw {
				t.Errorf("password %q round-tripped as %q; the DSN does not carry the "+
					"password the operator supplied", pw, got)
			}
			if u.Host != "127.0.0.1:5432" {
				t.Errorf("password %q corrupted the host: got %q, want 127.0.0.1:5432; "+
					"an unencoded character moved the URI boundary", pw, u.Host)
			}
			if u.User.Username() != "openwatch" {
				t.Errorf("password %q corrupted the username: got %q", pw, u.User.Username())
			}
		}
	})
}

// @ac AC-02
func TestPlan_DeriveComputesDependentFields(t *testing.T) {
	t.Run("system-setup/AC-02", func(t *testing.T) {
		p := DefaultPlan(Platform{})
		p.Service.ListenPort = 443
		p.Derive()
		if !p.Service.BindCapability {
			t.Error("port 443 must derive bind_capability=true; the service runs " +
				"unprivileged and cannot otherwise bind below 1024")
		}
		p.Service.ListenPort = 8443
		p.Derive()
		if p.Service.BindCapability {
			t.Error("port 8443 must not request CAP_NET_BIND_SERVICE")
		}
	})

	t.Run("system-setup/AC-02/remote database is not left in cleartext", func(t *testing.T) {
		p := DefaultPlan(Platform{})
		p.Database.Host = "db.internal"
		p.Derive()
		if p.Database.SSLMode == "disable" {
			t.Error("a non-loopback host must not keep sslmode=disable; credentials " +
				"would cross the network in cleartext")
		}
	})
}

// @ac AC-03
func TestPlan_ValidateRejectsUnsafeCombinations(t *testing.T) {
	cases := []struct {
		name string
		edit func(*Plan)
		want string
	}{
		{"provision a remote host", func(p *Plan) {
			p.Database.Mode = DBProvision
			p.Database.Host = "db.internal"
		}, "only provisions a local"},
		{"remote cleartext", func(p *Plan) {
			p.Database.Mode = DBExisting
			p.Database.Host = "db.internal"
			p.Database.SSLMode = "disable"
		}, "cleartext"},
		{"sql-unsafe database name", func(p *Plan) {
			p.Database.Name = "open;DROP TABLE users--"
		}, "plain identifier"},
		{"sql-unsafe role name", func(p *Plan) {
			p.Database.RoleName = `open"watch`
		}, "plain identifier"},
		{"identifier starting with a digit", func(p *Plan) {
			p.Database.Name = "9lives"
		}, "plain identifier"},
		{"port out of range", func(p *Plan) { p.Service.ListenPort = 70000 }, "out of range"},
		{"bad sslmode", func(p *Plan) { p.Database.SSLMode = "sorta" }, "sslmode"},
		{"email without @", func(p *Plan) { p.Admin.Email = "nobody" }, "not an address"},
		{"env secret with no ref", func(p *Plan) {
			p.Admin.Password = Secret{Source: SecretEnv}
		}, "ref is empty"},
		{"generated secret too short", func(p *Plan) {
			p.Database.Password = Secret{Source: SecretGenerate, Length: 4}
		}, "too short"},
	}
	for _, c := range cases {
		t.Run("system-setup/AC-03/"+c.name, func(t *testing.T) {
			p := DefaultPlan(Platform{})
			c.edit(&p)
			// Deliberately NOT calling Derive: Derive fixes defaults nobody
			// edited, and Validate must still catch a value someone set.
			errs := p.Validate()
			if len(errs) == 0 {
				t.Fatalf("expected a validation error mentioning %q, got none", c.want)
			}
			found := false
			for _, e := range errs {
				if contains(e.Error(), c.want) {
					found = true
				}
			}
			if !found {
				t.Errorf("no error mentioned %q; got %v", c.want, errs)
			}
		})
	}
}

// @ac AC-03
func TestPlan_DefaultIsValid(t *testing.T) {
	t.Run("system-setup/AC-03", func(t *testing.T) {
		p := DefaultPlan(Platform{ID: "rhel", VersionID: "9.8", Major: 9, Family: FamilyRHEL, Support: SupportTested})
		p.Derive()
		if errs := p.Validate(); len(errs) != 0 {
			t.Errorf("the default plan must validate; got %v", errs)
		}
		// The default must not edit pg_hba.conf. Editing it by hand is what locked
		// an operator out of local postgres access during a v0.7.0 install, so the
		// destructive option is opt-in.
		if p.Database.ManagePgHba {
			t.Error("manage_pg_hba must default to false")
		}
	})
}

func contains(haystack, needle string) bool {
	return len(needle) == 0 || len(haystack) >= len(needle) &&
		(haystack == needle || indexOf(haystack, needle) >= 0)
}

func indexOf(h, n string) int {
	for i := 0; i+len(n) <= len(h); i++ {
		if h[i:i+len(n)] == n {
			return i
		}
	}
	return -1
}
