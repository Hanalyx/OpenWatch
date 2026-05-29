// @spec system-event-bus
//
// AC traceability (this file):
//   AC-12  TestNoExternalBrokerImports

package eventbus

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

// @ac AC-12
// AC-12: internal/eventbus source files import no external broker
// packages. The bus is strictly in-process — Go channels only.
// If/when cross-process delivery is needed, a separate bridge sits
// alongside, not inside, the bus.
func TestNoExternalBrokerImports(t *testing.T) {
	t.Run("system-event-bus/AC-12", func(t *testing.T) {
		dir := packageDir(t)
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("read dir: %v", err)
		}

		// Known external broker prefixes. Reviewers add to this list
		// when new brokers come on the market.
		forbiddenPrefixes := []string{
			"github.com/segmentio/kafka",
			"github.com/Shopify/sarama",      // kafka client
			"github.com/IBM/sarama",
			"github.com/confluentinc/confluent-kafka",
			"github.com/nats-io",             // NATS
			"github.com/streadway/amqp",      // RabbitMQ
			"github.com/rabbitmq",
			"github.com/redis/go-redis",      // redis pub/sub
			"github.com/go-redis/redis",
			"cloud.google.com/go/pubsub",     // GCP Pub/Sub
			"github.com/aws/aws-sdk-go-v2/service/sns",
			"github.com/aws/aws-sdk-go-v2/service/sqs",
		}

		fset := token.NewFileSet()
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
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
						t.Errorf("%s imports %q — eventbus is in-process only (AC-12); external brokers go in a separate bridge package",
							f, path)
					}
				}
			}
		}
	})
}
