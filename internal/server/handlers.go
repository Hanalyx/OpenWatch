package server

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/Hanalyx/openwatch/internal/activity"
	"github.com/Hanalyx/openwatch/internal/alerts"
	"github.com/Hanalyx/openwatch/internal/audit"
	"github.com/Hanalyx/openwatch/internal/auth"
	"github.com/Hanalyx/openwatch/internal/correlation"
	"github.com/Hanalyx/openwatch/internal/credential"
	"github.com/Hanalyx/openwatch/internal/eventbus"
	"github.com/Hanalyx/openwatch/internal/exception"
	"github.com/Hanalyx/openwatch/internal/fleetrollup"
	"github.com/Hanalyx/openwatch/internal/group"
	"github.com/Hanalyx/openwatch/internal/host"
	"github.com/Hanalyx/openwatch/internal/intelligence/discovery"
	"github.com/Hanalyx/openwatch/internal/kensa"
	"github.com/Hanalyx/openwatch/internal/license"
	"github.com/Hanalyx/openwatch/internal/liveness"
	"github.com/Hanalyx/openwatch/internal/policy"
	"github.com/Hanalyx/openwatch/internal/queue"
	"github.com/Hanalyx/openwatch/internal/server/api"
	"github.com/Hanalyx/openwatch/internal/systemconfig"
	"github.com/Hanalyx/openwatch/internal/users"
	"github.com/Hanalyx/openwatch/internal/version"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	openapitypes "github.com/oapi-codegen/runtime/types"
)

// handlers implements api.ServerInterface for the Stage-0 endpoints.
//
// Each method is intentionally small: the heavy lifting lives in the
// middleware chain (correlation, idempotency) and the foundation
// packages (audit). The handler's job is request/response shaping and
// orchestration, nothing more.
type handlers struct {
	pool        *pgxpool.Pool
	users       *users.Service
	credentials *credential.Service
	hosts       *host.Service
	fleet       *fleetrollup.Service

	// Connectivity-monitor wiring. Set via (*Server).WithConnectivityConfig
	// before Run; nil in tests that don't exercise these endpoints.
	// Spec api-system-connectivity, api-host-connectivity-check.
	sysCfg  *systemconfig.Store
	liveSvc *liveness.Service

	// SSE fan-out. Set via (*Server).WithEventBus before Run; nil
	// disables the live-events stream (tests + early-boot phases).
	// Spec api-events-stream (Track B).
	bus *eventbus.Bus

	// Discovery wiring. Set via (*Server).WithDiscovery; nil in tests
	// that don't exercise /hosts/{id}/discovery:run.
	// Spec system-host-discovery.
	discoSvc *discovery.Service

	// Alerts lifecycle. Set via (*Server).WithAlerts; nil in tests
	// that don't exercise /alerts.
	// Spec system-alerts + api-alerts.
	alertsSvc *alerts.Service

	// Activity feed. Set via (*Server).WithActivity; nil in tests
	// that don't exercise /activity.
	// Spec system-activity + api-activity.
	activitySvc *activity.Service

	// On-demand scan enqueue. Set via (*Server).WithScanQueue; nil
	// disables POST /hosts/{id}/scans (503), e.g. in tests that don't
	// exercise it. The key is scheduler.DeriveQueueKey output — the
	// same HMAC key the worker verifies. Spec api-host-scan.
	scanQueueKey []byte

	// Compliance exception governance service. Set via
	// (*Server).WithExceptions; nil makes the exception endpoints 503.
	exceptionSvc *exception.Service

	// Host group service (sites + OS categories). Set via
	// (*Server).WithGroups; nil makes the group endpoints 503.
	// Spec api-groups.
	groupSvc *group.Service

	// Kensa variable catalog (corpus-used template variables). Set via
	// (*Server).WithVariableCatalog; nil renders an empty variables
	// list and rejects every override name.
	varCatalog *kensa.VariableCatalog

	// Kensa rule catalog. Set via (*Server).WithRuleCatalog; nil is
	// fine — the failed-rules endpoint falls back to rule ids for
	// titles. Spec api-host-compliance.
	ruleCatalog *kensa.RuleCatalog
}

// newHandlers constructs the ServerInterface implementation. The user
// service is built off the same pool; production passes a real breach
// corpus if one is configured, tests can pass nil.
func newHandlers(pool *pgxpool.Pool) *handlers {
	return &handlers{
		pool:        pool,
		users:       users.NewService(pool, nil),
		credentials: credential.NewService(pool),
		hosts:       host.NewService(pool),
		fleet:       fleetrollup.NewService(pool),
	}
}

// GetHealth implements api.ServerInterface.GetHealth.
// Spec: app/specs/api/health.spec.yaml.
func (h *handlers) GetHealth(w http.ResponseWriter, r *http.Request) {
	// 2-second timeout per spec constraint.
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()

	db := h.pool.Ping(ctx) == nil

	if !db {
		writeError(w, http.StatusServiceUnavailable, "server.unavailable", "server",
			"database is not reachable", true)
		return
	}

	writeJSON(w, http.StatusOK, api.HealthResponse{
		Status:      "healthy",
		DbConnected: true,
		Version:     version.Version,
	})
}

// GetVersion implements api.ServerInterface.GetVersion.
// Spec: specs/api/version.spec.yaml. Anonymous, read-only build metadata — no
// DB access, no audit emit. Every field is sourced from build-time metadata
// (ldflags) or the runtime/build info; nothing is hardcoded.
func (h *handlers) GetVersion(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, api.VersionResponse{
		Openwatch: version.Version,
		Kensa:     version.Kensa(),
		Go:        version.Go(),
		Commit:    version.Commit,
		BuildTime: version.BuildTime,
	})
}

// PostDiagnosticsEcho implements api.ServerInterface.PostDiagnosticsEcho.
// Spec: app/specs/api/diagnostics-echo.spec.yaml.
func (h *handlers) PostDiagnosticsEcho(w http.ResponseWriter, r *http.Request, params api.PostDiagnosticsEchoParams) {
	// Per spec AC-3: Idempotency-Key is required (oapi-codegen enforces
	// header presence via the params struct).
	if strings.TrimSpace(params.IdempotencyKey) == "" {
		writeError(w, http.StatusBadRequest, "idempotency.key_required", "client",
			"Idempotency-Key header is required", false)
		return
	}

	var req api.EchoRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "validation.field_required", "client",
			"request body must be JSON with required field 'message'", false)
		return
	}
	if strings.TrimSpace(req.Message) == "" {
		writeError(w, http.StatusBadRequest, "validation.field_required", "client",
			"message is required and must not be empty", false)
		return
	}
	if len(req.Message) > 1024 {
		writeError(w, http.StatusBadRequest, "validation.field_range", "client",
			"message exceeds maximum length of 1024 characters", false)
		return
	}

	corrID, _ := correlation.From(r.Context())

	// Per spec AC-6: emit exactly one audit event. Idempotency middleware
	// short-circuits replays before reaching this handler.
	eventID := uuid.Must(uuid.NewV7())
	audit.Emit(r.Context(), audit.IntegrationPluginExecuted, audit.Event{
		ID:        eventID,
		ActorType: "user",
		Action:    audit.IntegrationPluginExecuted, // placeholder until diagnostics.* code exists
		Detail: audit.MakeDetail(map[string]interface{}{
			"endpoint": "diagnostics:echo",
			"message":  req.Message,
			"actor":    "stage-0-demo",
		}),
	})

	auditUUID := openapitypes.UUID(eventID)
	writeJSON(w, http.StatusOK, api.EchoResponse{
		Echoed:        req.Message,
		CorrelationId: corrID,
		AuditEventId:  &auditUUID,
	})
}

// GetLicense returns the current runtime license state.
// Spec: app/specs/api/license.spec.yaml AC-1, AC-2, AC-3.
func (h *handlers) GetLicense(w http.ResponseWriter, r *http.Request) {
	state := license.CurrentState()

	resp := api.LicenseStateResponse{
		Tier:     api.LicenseStateResponseTier(license.TierFree),
		Status:   api.LicenseStateResponseStatus(license.StatusNoLicense),
		Features: stageZeroFreeFeatures(),
	}

	if state != nil && state.License != nil {
		lic := state.License
		resp.Tier = api.LicenseStateResponseTier(lic.Tier)
		resp.Status = api.LicenseStateResponseStatus(lic.Status)
		resp.Features = featuresToStrings(lic.Features)
		resp.CustomerId = &lic.CustomerID
		exp := lic.ExpiresAt
		resp.ExpiresAt = &exp
		grace := lic.InGracePeriod
		resp.InGracePeriod = &grace
		prev := lic.UsingPrevKey
		resp.UsingPrevKey = &prev
	}
	writeJSON(w, http.StatusOK, resp)
}

// PostAdminLicenseVerify dry-run validates a JWT without installing.
// Spec: app/specs/api/license.spec.yaml AC-4, AC-5, AC-6.
func (h *handlers) PostAdminLicenseVerify(w http.ResponseWriter, r *http.Request) {
	var req api.LicenseVerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "validation.field_required", "client",
			"license_jwt is required", false)
		return
	}
	if strings.TrimSpace(req.LicenseJwt) == "" {
		writeError(w, http.StatusBadRequest, "validation.field_required", "client",
			"license_jwt must not be empty", false)
		return
	}

	lic, result, err := license.VerifyOnly(req.LicenseJwt, license.VerifyOptions{})
	resp := api.LicenseVerifyResponse{
		IsValid:      result == license.VerifyValid,
		VerifyResult: string(result),
	}
	if lic != nil {
		tier := string(lic.Tier)
		resp.Tier = &tier
		feats := featuresToStrings(lic.Features)
		resp.Features = &feats
		exp := lic.ExpiresAt
		resp.ExpiresAt = &exp
		warnings := []string{}
		if lic.UsingPrevKey {
			warnings = append(warnings, "signed with previous key; rotate at next renewal")
		}
		if lic.InGracePeriod {
			warnings = append(warnings, "license expired but within 30-day grace period")
		}
		resp.Warnings = &warnings
	}
	_ = err // surfaced via verify_result, not response body
	writeJSON(w, http.StatusOK, resp)
}

// PostDiagnosticsPremiumEcho is the Stage-0 license-gated demo endpoint.
// Checks the premium_diagnostics feature gate via license.EnforceFeature
// (oapi-codegen-mounted routes can't easily take per-route middleware).
//
// Spec: app/specs/api/license.spec.yaml AC-7, AC-9.
func (h *handlers) PostDiagnosticsPremiumEcho(w http.ResponseWriter, r *http.Request, params api.PostDiagnosticsPremiumEchoParams) {
	// License gate FIRST so we don't burn an audit event for input that
	// would have been denied anyway.
	if license.EnforceFeature(w, r, license.PremiumDiagnostics) {
		return
	}
	if strings.TrimSpace(params.IdempotencyKey) == "" {
		writeError(w, http.StatusBadRequest, "idempotency.key_required", "client",
			"Idempotency-Key header is required", false)
		return
	}

	var req api.EchoRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "validation.field_required", "client",
			"request body must include 'message'", false)
		return
	}

	corrID, _ := correlation.From(r.Context())

	eventID := uuid.Must(uuid.NewV7())
	audit.Emit(r.Context(), audit.IntegrationPluginExecuted, audit.Event{
		ID:        eventID,
		ActorType: "user",
		Detail: audit.MakeDetail(map[string]interface{}{
			"endpoint": "diagnostics:premium-echo",
			"message":  req.Message,
			"gated_by": string(license.PremiumDiagnostics),
		}),
	})

	auditUUID := openapitypes.UUID(eventID)
	writeJSON(w, http.StatusOK, api.EchoResponse{
		Echoed:        "PREMIUM: " + req.Message,
		CorrelationId: corrID,
		AuditEventId:  &auditUUID,
	})
}

func featuresToStrings(fs []license.Feature) []string {
	out := make([]string, len(fs))
	for i, f := range fs {
		out[i] = string(f)
	}
	return out
}

// stageZeroFreeFeatures returns the free-tier feature list for the
// no-license response. Reads from the registry so adding a new free
// feature requires only a registry edit.
func stageZeroFreeFeatures() []string {
	var out []string
	for f, meta := range license.FeatureRegistry {
		if meta.Tier == license.TierFree {
			out = append(out, string(f))
		}
	}
	return out
}

// GetAuditEvents implements api.ServerInterface.GetAuditEvents.
// Spec: app/specs/api/audit-events-query.spec.yaml.
func (h *handlers) GetAuditEvents(w http.ResponseWriter, r *http.Request, params api.GetAuditEventsParams) {
	limit := int32(50)
	if params.Limit != nil {
		// Bound BEFORE narrowing to int32 — guards against negative or
		// > 2B inputs that would overflow the conversion.
		v := *params.Limit
		if v < 0 || v > 200 {
			writeError(w, http.StatusBadRequest, "pagination.limit_exceeded", "client",
				"limit must be between 0 and 200", false)
			return
		}
		limit = int32(v)
	}

	rows, err := h.queryEvents(r.Context(), params, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server.internal", "server",
			"failed to query audit events", true)
		return
	}

	items := make([]api.AuditEvent, 0, len(rows))
	for _, row := range rows {
		items = append(items, row)
	}

	resp := api.AuditEventsPage{Items: items}
	if len(rows) == int(limit) {
		// More may exist; emit a next_cursor. Stage-0 cursor is the
		// boundary row's occurred_at; Stage-2 will use opaque tokens.
		last := rows[len(rows)-1].OccurredAt.Format(time.RFC3339Nano)
		resp.NextCursor = &last
	}
	writeJSON(w, http.StatusOK, resp)
}

// queryEvents reads audit_events from the DB with the given filters.
// Returns at most limit rows newest-first.
func (h *handlers) queryEvents(ctx context.Context, p api.GetAuditEventsParams, limit int32) ([]api.AuditEvent, error) {
	q := `
SELECT id, correlation_id, action, severity,
       actor_type, actor_id, resource_type, resource_id,
       occurred_at, recorded_at, detail, redactions
FROM audit_events
WHERE 1=1
`
	args := []interface{}{}
	idx := 1
	addArg := func(condition string, val interface{}) {
		q += " AND " + strings.Replace(condition, "$N", "$"+itoa(idx), 1)
		args = append(args, val)
		idx++
	}

	if p.Action != nil && *p.Action != "" {
		addArg("action = $N", *p.Action)
	}
	if p.CorrelationId != nil && *p.CorrelationId != "" {
		addArg("correlation_id = $N", *p.CorrelationId)
	}
	if p.ActorType != nil && *p.ActorType != "" {
		addArg("actor_type = $N", *p.ActorType)
	}
	if p.Since != nil {
		addArg("occurred_at >= $N", *p.Since)
	}
	if p.Until != nil {
		addArg("occurred_at < $N", *p.Until)
	}
	if p.Cursor != nil && *p.Cursor != "" {
		if t, err := time.Parse(time.RFC3339Nano, *p.Cursor); err == nil {
			addArg("occurred_at < $N", t)
		}
	}

	q += " ORDER BY occurred_at DESC, id DESC LIMIT $" + itoa(idx)
	args = append(args, limit)

	rows, err := h.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []api.AuditEvent
	for rows.Next() {
		var (
			ev           api.AuditEvent
			id           uuid.UUID
			severity     *string
			actorID      *string
			resourceType *string
			resourceID   *string
			detailBytes  []byte
			redactions   []string
		)
		if err := rows.Scan(
			&id, &ev.CorrelationId, &ev.Action, &severity,
			&ev.ActorType, &actorID, &resourceType, &resourceID,
			&ev.OccurredAt, &ev.RecordedAt, &detailBytes, &redactions,
		); err != nil {
			return nil, err
		}
		ev.Id = id
		ev.Severity = severity
		ev.ActorId = actorID
		ev.ResourceType = resourceType
		ev.ResourceId = resourceID
		if len(detailBytes) > 0 {
			var d map[string]interface{}
			if err := json.Unmarshal(detailBytes, &d); err == nil {
				ev.Detail = &d
			}
		}
		ev.Redactions = &redactions
		out = append(out, ev)
	}
	return out, rows.Err()
}

// writeJSON writes a JSON response with status code; Content-Type is set
// explicitly so the idempotency middleware's recorder captures it.
func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	body, err := json.Marshal(v)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server.internal", "server",
			"failed to encode response", true)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

// writeError emits the canonical error envelope per app/api/error_codes.yaml.
func writeError(w http.ResponseWriter, status int, code, fault, msg string, retryable bool) {
	env := api.ErrorEnvelope{}
	env.Error.Code = code
	env.Error.Fault = api.ErrorEnvelopeErrorFault(fault)
	env.Error.Retryable = retryable
	env.Error.HumanMessage = msg
	body, _ := json.Marshal(env)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

// itoa avoids strconv for the one site we use it; small ints only.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	const digits = "0123456789"
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = digits[n%10]
		n /= 10
	}
	return string(buf[i:])
}

// PostDiagnosticsRequireHostRead is the Stage-0 RBAC demo: x-required-permission:
// host:read. Permission enforcement is inline because oapi-codegen mounts
// every handler at once; per-route chi middleware injection is awkward.
// Spec system-rbac AC-08, AC-09.
func (h *handlers) PostDiagnosticsRequireHostRead(w http.ResponseWriter, r *http.Request, _ api.PostDiagnosticsRequireHostReadParams) {
	if denied := auth.EnforcePermission(w, r, auth.HostRead); denied {
		return
	}
	requireDiagnosticEcho(w, r, h.pool, "diagnostics:require-host-read")
}

// PostDiagnosticsRequireHostWrite is the Stage-0 RBAC-denial demo used by
// DoD step 12: viewer role lacks host:write, so this 403s.
// Spec release-stage-0-signoff AC-06.
func (h *handlers) PostDiagnosticsRequireHostWrite(w http.ResponseWriter, r *http.Request, _ api.PostDiagnosticsRequireHostWriteParams) {
	if denied := auth.EnforcePermission(w, r, auth.HostWrite); denied {
		return
	}
	requireDiagnosticEcho(w, r, h.pool, "diagnostics:require-host-write")
}

// PostDiagnosticsRequireRemediationExecute is the Stage-0 demo combining
// RBAC + license: x-required-permission: remediation:execute,
// x-required-feature: remediation_execution. RBAC fails first (403),
// license fails second (402). Spec system-rbac AC-09, AC-10.
func (h *handlers) PostDiagnosticsRequireRemediationExecute(w http.ResponseWriter, r *http.Request, _ api.PostDiagnosticsRequireRemediationExecuteParams) {
	if denied := auth.EnforcePermission(w, r, auth.RemediationExecute); denied {
		return
	}
	requireDiagnosticEcho(w, r, h.pool, "diagnostics:require-remediation-execute")
}

// requireDiagnosticEcho is the shared body for the RBAC demo endpoints.
// Returns the echoed message + audit_event_id, same shape as :echo.
func requireDiagnosticEcho(w http.ResponseWriter, r *http.Request, _ *pgxpool.Pool, endpointLabel string) {
	var req api.EchoRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "validation.field_required", "client",
			"message is required", false)
		return
	}
	if strings.TrimSpace(req.Message) == "" {
		writeError(w, http.StatusBadRequest, "validation.field_required", "client",
			"message must not be empty", false)
		return
	}
	if len(req.Message) > 1024 {
		writeError(w, http.StatusBadRequest, "validation.field_range", "client",
			"message exceeds 1024 char limit", false)
		return
	}

	corrID, _ := correlation.From(r.Context())
	eventID := uuid.Must(uuid.NewV7())
	audit.Emit(r.Context(), audit.IntegrationPluginExecuted, audit.Event{
		ID:        eventID,
		ActorType: "user",
		Action:    audit.IntegrationPluginExecuted,
		Detail: audit.MakeDetail(map[string]interface{}{
			"endpoint": endpointLabel,
			"message":  req.Message,
		}),
	})
	auditUUID := openapitypes.UUID(eventID)
	writeJSON(w, http.StatusOK, api.EchoResponse{
		Echoed:        req.Message,
		CorrelationId: corrID,
		AuditEventId:  &auditUUID,
	})
}

// GetAuthMePermissions returns the calling identity's effective permission
// list. Spec system-rbac AC-13.
func (h *handlers) GetAuthMePermissions(w http.ResponseWriter, r *http.Request) {
	id := auth.FromContext(r.Context())
	perms := id.Permissions()
	out := make([]string, len(perms))
	for i, p := range perms {
		out[i] = string(p)
	}
	// The inline struct mirrors the oapi-codegen output shape exactly;
	// the `Id` field name (not `ID`) is what the generated type expects.
	writeJSON(w, http.StatusOK, api.AuthMePermissionsResponse{
		Identity: struct {
			Id          string `json:"id"` //nolint:revive // mirrors codegen field name
			IsAnonymous bool   `json:"is_anonymous"`
			Role        string `json:"role"`
		}{
			Id:          id.ID, //nolint:revive // mirrors codegen field name
			Role:        string(id.RoleID),
			IsAnonymous: id.IsAnonymous,
		},
		Permissions: out,
	})
}

// GetAuthPermissionsRegistry returns the full registry — categories,
// permissions, and built-in roles. Spec system-rbac AC-14.
func (h *handlers) GetAuthPermissionsRegistry(w http.ResponseWriter, _ *http.Request) {
	cats := make([]api.CategoryEntry, 0, len(auth.Categories()))
	for _, id := range auth.Categories() {
		cats = append(cats, api.CategoryEntry{
			Id:          id,
			Description: auth.CategoryDescription(id),
		})
	}
	perms := make([]api.PermissionEntry, 0, len(auth.Permissions))
	for _, p := range auth.AllPermissions() {
		meta := auth.Permissions[p]
		gated := meta.LicenseGated
		entry := api.PermissionEntry{
			Id:          string(p),
			Category:    meta.Category,
			Description: meta.Description,
			Dangerous:   meta.Dangerous,
		}
		if gated != "" {
			entry.LicenseGated = &gated
		}
		perms = append(perms, entry)
	}
	roles := buildRoleEntries()
	writeJSON(w, http.StatusOK, api.PermissionsRegistryResponse{
		Categories:  cats,
		Permissions: perms,
		Roles:       roles,
	})
}

// GetRoles returns the 5 built-in roles. Spec system-rbac AC-15.
func (h *handlers) GetRoles(w http.ResponseWriter, r *http.Request) {
	if denied := auth.EnforcePermission(w, r, auth.RoleRead); denied {
		return
	}
	writeJSON(w, http.StatusOK, api.AdminRolesResponse{Roles: buildRoleEntries()})
}

func buildRoleEntries() []api.RoleEntry {
	ids := auth.BuiltInRoleIDs()
	out := make([]api.RoleEntry, 0, len(ids))
	for _, id := range ids {
		def := auth.BuiltInRoles[id]
		perms := make([]string, len(def.Permissions))
		for i, p := range def.Permissions {
			perms[i] = string(p)
		}
		out = append(out, api.RoleEntry{
			Id:          string(def.ID),
			Description: def.Description,
			IsBuiltIn:   def.IsBuiltIn,
			Permissions: perms,
		})
	}
	return out
}

// PostDiagnosticsEvaluateAlert evaluates the alert_thresholds policy
// against the supplied score and returns the resulting Decision.
// Spec release-stage-0-signoff AC-08.
func (h *handlers) PostDiagnosticsEvaluateAlert(w http.ResponseWriter, r *http.Request) {
	var req api.EvaluateAlertRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "validation.field_required", "client",
			"score is required", false)
		return
	}
	if req.Score < 0 || req.Score > 100 {
		writeError(w, http.StatusBadRequest, "validation.field_range", "client",
			"score must be in [0, 100]", false)
		return
	}
	d := policy.EvaluateAlert(r.Context(), policy.AlertInput{Score: req.Score})

	human := d.HumanMessage
	resp := api.PolicyDecisionResponse{
		Outcome:       string(d.Outcome),
		PolicyType:    string(d.PolicyType),
		PolicyVersion: d.PolicyVersion,
		Reason:        d.Reason,
		HumanMessage:  &human,
	}
	if d.Detail != nil {
		detail := map[string]interface{}(d.Detail)
		resp.Detail = &detail
	}
	writeJSON(w, http.StatusOK, resp)
}

// PostDiagnosticsEnqueueTestJob enqueues a diagnostics.test_job; the
// in-process worker drains it and emits diagnostics.test_job_completed
// carrying the request's correlation_id.
// Spec release-stage-0-signoff AC-10.
func (h *handlers) PostDiagnosticsEnqueueTestJob(w http.ResponseWriter, r *http.Request) {
	jobID, err := queue.Enqueue(r.Context(), h.pool, "diagnostics.test_job", nil)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "queue.enqueue_failed", "server",
			err.Error(), false)
		return
	}
	corrID, _ := correlation.From(r.Context())
	writeJSON(w, http.StatusAccepted, api.EnqueueTestJobResponse{
		JobId:         openapitypes.UUID(jobID),
		CorrelationId: corrID,
	})
}

// PostAdminPoliciesReload re-reads policy files from the configured
// directory (OPENWATCH_POLICIES_DIR or /etc/openwatch/policies) and
// returns a per-type outcome map. Spec release-stage-0-signoff AC-09.
func (h *handlers) PostAdminPoliciesReload(w http.ResponseWriter, r *http.Request) {
	if denied := auth.EnforcePermission(w, r, auth.PolicyReload); denied {
		return
	}
	dir := os.Getenv("OPENWATCH_POLICIES_DIR")
	if dir == "" {
		dir = "/etc/openwatch/policies"
	}
	outcomes, err := policy.ReloadDir(r.Context(), h.pool, dir)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "policy.reload_failed", "server",
			err.Error(), false)
		return
	}
	resp := api.PoliciesReloadResponse{Outcomes: map[string]string{}}
	for typ, outcome := range outcomes {
		resp.Outcomes[string(typ)] = string(outcome)
	}
	writeJSON(w, http.StatusOK, resp)
}
