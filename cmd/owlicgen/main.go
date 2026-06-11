// owlicgen mints signed Ed25519 license JWTs for testing.
//
// Usage:
//
//	owlicgen --features premium_diagnostics,remediation_execution \
//	         --tier openwatch_plus \
//	         --customer test-customer \
//	         --days 30 \
//	         --output /tmp/test.lic
//
// Reads the test private key from internal/license/testdata. Production
// licenses are minted by Hanalyx infra using the offline private key;
// this tool exists for Stage-0 acceptance, integration tests, and
// developer self-service.
package main

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	defaultKeyPath = "internal/license/testdata/license-privkey-test.pem"
	defaultIssuer  = "hanalyx-openwatch-licensing"
	defaultAud     = "openwatch"
)

func main() {
	var (
		features    = flag.String("features", "premium_diagnostics", "comma-separated feature ids")
		tier        = flag.String("tier", "openwatch_plus", "license tier (free|openwatch_plus|enterprise)")
		customer    = flag.String("customer", "test-customer", "customer id")
		days        = flag.Int("days", 30, "validity period in days")
		output      = flag.String("output", "/tmp/test.lic", "output file")
		keyPath     = flag.String("key", defaultKeyPath, "path to Ed25519 private key (PEM PKCS#8)")
		fingerprint = flag.String("fingerprint", "", "bind to this deployment fingerprint (empty = portable)")
	)
	flag.Parse()

	priv, err := loadPrivKey(*keyPath)
	if err != nil {
		fail("load key: %v", err)
	}

	now := time.Now()
	featureList := splitCSV(*features)

	type licenseClaims struct {
		jwt.RegisteredClaims
		Tier        string   `json:"tier"`
		Features    []string `json:"features"`
		CustomerID  string   `json:"customer_id"`
		Fingerprint string   `json:"fingerprint,omitempty"`
	}

	claims := licenseClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    defaultIssuer,
			Audience:  jwt.ClaimStrings{defaultAud},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Duration(*days) * 24 * time.Hour)),
		},
		Tier:        *tier,
		Features:    featureList,
		CustomerID:  *customer,
		Fingerprint: *fingerprint,
	}

	tok := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	signed, err := tok.SignedString(priv)
	if err != nil {
		fail("sign: %v", err)
	}

	if err := os.WriteFile(*output, []byte(signed+"\n"), 0o600); err != nil {
		fail("write output: %v", err)
	}
	fmt.Printf("wrote license to %s\n", *output)
	fmt.Printf("  tier:     %s\n", *tier)
	fmt.Printf("  features: %v\n", featureList)
	fmt.Printf("  expires:  %s\n", claims.ExpiresAt.Time.Format(time.RFC3339))
	if *fingerprint != "" {
		fmt.Printf("  bound:    %s\n", *fingerprint)
	}
}

func loadPrivKey(path string) (ed25519.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in %s", path)
	}
	keyAny, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	priv, ok := keyAny.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%s is not an Ed25519 private key", path)
	}
	return priv, nil
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func fail(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "owlicgen: "+format+"\n", args...)
	os.Exit(1)
}
