// @spec system-http-server
package server

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/Hanalyx/openwatch/internal/auth"
)

// Spec: specs/system/http-server.spec.yaml
//
//	AC-20  TestRequestErrors_EnvelopeEverywhere

type envelopeBody struct {
	Error struct {
		Code          string `json:"code"`
		Fault         string `json:"fault"`
		HumanMessage  string `json:"human_message"`
		CorrelationID string `json:"correlation_id"`
	} `json:"error"`
}

func readEnvelope(t *testing.T, resp *http.Response) (envelopeBody, string) {
	t.Helper()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	var env envelopeBody
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("body is not the envelope: %v; body=%q", err, raw)
	}
	return env, string(raw)
}

// @ac AC-20
// AC-20: every 4xx the process itself generates is the envelope, including
// the three that no handler produces: an unmatched /api/ path, a method the
// route does not accept, and a parameter that fails to bind. The parameter
// message names the parameter and never repeats the rejected value.
func TestRequestErrors_EnvelopeEverywhere(t *testing.T) {
	t.Run("system-http-server/AC-20", func(t *testing.T) {
		srv, _ := freshAPIServer(t)

		cases := []struct {
			name      string
			req       *http.Request
			status    int
			code      string
			mentions  string
			forbidden string
		}{
			{
				name:   "unmatched /api/ path is a 404 envelope",
				req:    asRole(t, "GET", srv+"/api/v1/definitely-not-a-route", auth.RoleViewer, nil),
				status: http.StatusNotFound, code: "request.not_found",
			},
			{
				name:   "method the route does not accept is a 405 envelope",
				req:    asRole(t, "DELETE", srv+"/api/v1/health", auth.RoleViewer, nil),
				status: http.StatusMethodNotAllowed, code: "request.method_not_allowed",
			},
			{
				name:   "parameter that fails to bind is a 400 envelope naming the parameter only",
				req:    asRole(t, "GET", srv+"/api/v1/audit/events?limit=abc", auth.RoleViewer, nil),
				status: http.StatusBadRequest, code: "request.invalid_parameter",
				mentions: "limit", forbidden: "abc",
			},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				resp := doReq(t, tc.req)
				defer resp.Body.Close()
				if resp.StatusCode != tc.status {
					t.Fatalf("status = %d, want %d", resp.StatusCode, tc.status)
				}
				if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
					t.Errorf("Content-Type = %q, want application/json", ct)
				}
				if resp.Header.Get("X-Correlation-Id") == "" {
					t.Errorf("no X-Correlation-Id header on the error response")
				}
				env, raw := readEnvelope(t, resp)
				if env.Error.Code != tc.code {
					t.Errorf("error.code = %q, want %q", env.Error.Code, tc.code)
				}
				if env.Error.Fault != "client" {
					t.Errorf("error.fault = %q, want client", env.Error.Fault)
				}
				if tc.mentions != "" && !strings.Contains(env.Error.HumanMessage, tc.mentions) {
					t.Errorf("human_message %q does not name %q", env.Error.HumanMessage, tc.mentions)
				}
				if tc.forbidden != "" && strings.Contains(raw, tc.forbidden) {
					t.Errorf("body echoes the rejected value %q: %s", tc.forbidden, raw)
				}
			})
		}

		// Structural half: no bare http.Error in the package outside tests
		// and generated code, so a new plain-text error cannot be added
		// without this criterion noticing.
		t.Run("no bare http.Error in internal/server", func(t *testing.T) {
			files, err := filepath.Glob("*.go")
			if err != nil {
				t.Fatal(err)
			}
			bare := regexp.MustCompile(`\bhttp\.Error\(`)
			for _, f := range files {
				if strings.HasSuffix(f, "_test.go") {
					continue
				}
				src, err := os.ReadFile(f)
				if err != nil {
					t.Fatal(err)
				}
				if bare.Match(src) {
					t.Errorf("%s calls http.Error; use writeError so the response is the envelope (C-15)", f)
				}
			}
		})
	})
}
