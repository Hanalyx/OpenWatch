// Bus publishers for host CRUD events. The SSE layer subscribes to
// host.changed and fans the event out to operator browsers so list +
// detail pages refresh in place without polling.
//
// Spec: app/specs/api/events-stream.spec.yaml.

package server

import (
	"context"
	"time"

	"github.com/Hanalyx/openwatch/internal/eventbus"
	"github.com/google/uuid"
)

// publishHostChange is a tiny convenience wrapper around bus.Publish
// that's safe when h.bus is nil (tests, early-boot paths). Used by
// the host CRUD handlers immediately after they emit the audit event,
// so the wire shape stays consistent.
func (h *handlers) publishHostChange(ctx context.Context, hostID uuid.UUID, change eventbus.HostChangeKind) {
	if h.bus == nil {
		return
	}
	h.bus.Publish(ctx, eventbus.HostChanged{
		HostID:     hostID,
		Change:     change,
		OccurredAt: time.Now().UTC(),
	})
}
