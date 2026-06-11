// @spec system-alert-router
//
// AC traceability (this file):
//   AC-13  TestNoExternalNotificationSDKImports

package alertrouter

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func packageDir(t *testing.T) string {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	return filepath.Dir(file)
}

// @ac AC-13
// AC-13: internal/alertrouter (core package, NOT subpackages) imports
// no external notification SDKs. Channel implementations live in
// subpackages so the core router stays dependency-light and the
// boundary is enforceable at the source level.
func TestNoExternalNotificationSDKImports(t *testing.T) {
	t.Run("system-alert-router/AC-13", func(t *testing.T) {
		dir := packageDir(t)
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("read dir: %v", err)
		}

		// Known external notification SDK prefixes. Reviewers extend
		// this list when a new SDK enters the ecosystem.
		forbiddenPrefixes := []string{
			"github.com/slack-go/slack",       // Slack
			"github.com/nlopes/slack",         // Slack (legacy)
			"github.com/sendgrid/sendgrid-go", // SendGrid
			"github.com/mailgun/mailgun-go",   // Mailgun
			"github.com/sendinblue/APIv3-go",  // Brevo (ex-Sendinblue)
			"github.com/twilio/twilio-go",     // Twilio (SMS)
			"github.com/PagerDuty/go-pagerduty",
			"github.com/opsgenie/opsgenie-go-sdk", // Opsgenie
			"gopkg.in/gomail.v2",                  // SMTP wrapper
			"github.com/jordan-wright/email",      // SMTP wrapper
		}

		fset := token.NewFileSet()
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") {
				continue
			}
			if strings.HasSuffix(e.Name(), "_test.go") {
				continue
			}
			f := filepath.Join(dir, e.Name())
			astFile, err := parser.ParseFile(fset, f, nil, parser.ImportsOnly)
			if err != nil {
				t.Fatalf("parse %s: %v", f, err)
			}
			for _, imp := range astFile.Imports {
				path := strings.Trim(imp.Path.Value, `"`)
				for _, bad := range forbiddenPrefixes {
					if strings.HasPrefix(path, bad) {
						t.Errorf("%s imports %q — core router must stay SDK-free (AC-13); channel implementations belong in subpackages",
							f, path)
					}
				}
			}
		}
	})
}
