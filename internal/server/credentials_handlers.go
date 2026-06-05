// Credential CRUD + resolver admin handlers. Spec:
// app/specs/api/credentials.spec.yaml.
//
// All read endpoints return metadata-only — no plaintext or ciphertext
// for password / private_key / passphrase ever crosses this layer.

package server

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/Hanalyx/openwatch/internal/audit"
	"github.com/Hanalyx/openwatch/internal/auth"
	"github.com/Hanalyx/openwatch/internal/credential"
	"github.com/Hanalyx/openwatch/internal/host"
	"github.com/Hanalyx/openwatch/internal/server/api"
	"github.com/Hanalyx/openwatch/internal/ssh"
	"github.com/google/uuid"
	openapitypes "github.com/oapi-codegen/runtime/types"
)

// GetCredentials lists active credentials.
// Spec api-credentials AC-07.
func (h *handlers) GetCredentials(w http.ResponseWriter, r *http.Request) {
	if denied := auth.EnforcePermission(w, r, auth.CredentialRead); denied {
		return
	}
	list, err := h.credentials.ListMetadata(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server.error", "server",
			"list credentials failed", true)
		return
	}
	out := make([]api.CredentialResponse, len(list))
	for i, m := range list {
		out[i] = credentialResponse(m)
	}
	writeJSON(w, http.StatusOK, api.CredentialListResponse{Credentials: out})
}

// PostCredentials creates a credential.
// Spec api-credentials AC-01, AC-03, AC-04, AC-05, AC-06.
func (h *handlers) PostCredentials(w http.ResponseWriter, r *http.Request) {
	if denied := auth.EnforcePermission(w, r, auth.CredentialWrite); denied {
		return
	}
	var req api.CredentialCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "validation.field_required", "client",
			"scope, name, username, auth_method required", false)
		return
	}

	// Translate the wire shape into the service NewParams.
	params, err := credentialParamsFromRequest(r, req, h.identityUUID(r))
	if err != nil {
		writeError(w, http.StatusBadRequest, "validation.field_invalid", "client",
			err.Error(), false)
		return
	}

	// AC-04: when scope=host, the host id MUST exist.
	if params.Scope == credential.ScopeHost && params.ScopeID != nil {
		if _, err := h.hosts.GetByID(r.Context(), *params.ScopeID); err != nil {
			if errors.Is(err, host.ErrHostNotFound) {
				writeError(w, http.StatusBadRequest, "credentials.host_not_found", "client",
					"scope_id does not match an active host", false)
				return
			}
			writeError(w, http.StatusInternalServerError, "server.error", "server",
				"host lookup failed", true)
			return
		}
	}

	// AC-05: SSH key inputs MUST pass NIST SP 800-57 validation.
	if params.PrivateKey != "" {
		if err := ssh.ValidateAuthKey([]byte(params.PrivateKey), params.PrivateKeyPassphrase); err != nil {
			writeError(w, http.StatusBadRequest, "credentials.invalid_key", "client",
				err.Error(), false)
			return
		}
	}

	id, err := h.credentials.NewCredential(r.Context(), params)
	if err != nil {
		switch {
		case errors.Is(err, credential.ErrInvalidScope):
			writeError(w, http.StatusBadRequest, "credentials.invalid_scope", "client",
				"scope and scope_id mismatch", false)
		case errors.Is(err, credential.ErrMissingSecret):
			writeError(w, http.StatusBadRequest, "credentials.missing_secret", "client",
				"required secret missing for auth_method", false)
		case errors.Is(err, credential.ErrUnknownAuthMethod):
			writeError(w, http.StatusBadRequest, "validation.field_invalid", "client",
				"unknown auth_method", false)
		case errors.Is(err, credential.ErrMultipleSystemDefaults):
			writeError(w, http.StatusConflict, "credentials.multiple_system_defaults", "client",
				"another system default already exists", false)
		default:
			writeError(w, http.StatusInternalServerError, "server.error", "server",
				err.Error(), true)
		}
		return
	}
	emitAudit(r, audit.CredentialCreated, id.String(), map[string]any{
		"credential_id": id.String(),
		"scope":         string(params.Scope),
		"auth_method":   string(params.AuthMethod),
	})

	created, err := h.credentials.GetMetadataByID(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server.error", "server",
			"create succeeded but lookup failed", true)
		return
	}
	writeJSON(w, http.StatusCreated, credentialResponse(created))
}

// GetCredentialByID fetches a credential's metadata.
// Spec api-credentials AC-08.
func (h *handlers) GetCredentialByID(w http.ResponseWriter, r *http.Request, id openapitypes.UUID) {
	if denied := auth.EnforcePermission(w, r, auth.CredentialRead); denied {
		return
	}
	m, err := h.credentials.GetMetadataByID(r.Context(), uuid.UUID(id))
	if err != nil {
		if errors.Is(err, credential.ErrNotFound) {
			writeError(w, http.StatusNotFound, "credentials.not_found", "client",
				"credential not found", false)
			return
		}
		writeError(w, http.StatusInternalServerError, "server.error", "server",
			"lookup failed", true)
		return
	}
	writeJSON(w, http.StatusOK, credentialResponse(m))
}

// PostCredentialClone copies the source credential's secret material
// into a new row with the target scope/scope_id. The bulk-import flow
// uses this to attach a chosen credential template to every newly
// imported host without re-prompting the operator for the key/password.
//
// Spec api-credentials v1.1.0 AC-13, AC-14, AC-15.
func (h *handlers) PostCredentialClone(w http.ResponseWriter, r *http.Request, srcID openapitypes.UUID) {
	if denied := auth.EnforcePermission(w, r, auth.CredentialWrite); denied {
		return
	}
	var req api.CredentialCloneRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "validation.field_required", "client",
			"scope is required", false)
		return
	}

	var scopeID *uuid.UUID
	if req.ScopeId != nil {
		u := uuid.UUID(*req.ScopeId)
		scopeID = &u
	}
	params := credential.CloneParams{
		SourceID: uuid.UUID(srcID),
		Scope:    credential.Scope(req.Scope),
		ScopeID:  scopeID,
	}
	if req.Name != nil {
		params.Name = *req.Name
	}
	if req.IsDefault != nil {
		params.IsDefault = *req.IsDefault
	}
	if creator := h.identityUUID(r); creator != nil {
		params.CreatedBy = *creator
	}

	// Mirror PostCredentials AC-04: when scope=host, the target host MUST exist.
	if params.Scope == credential.ScopeHost && params.ScopeID != nil {
		if _, err := h.hosts.GetByID(r.Context(), *params.ScopeID); err != nil {
			if errors.Is(err, host.ErrHostNotFound) {
				writeError(w, http.StatusBadRequest, "credentials.host_not_found", "client",
					"scope_id does not match an active host", false)
				return
			}
			writeError(w, http.StatusInternalServerError, "server.error", "server",
				"host lookup failed", true)
			return
		}
	}

	newID, err := h.credentials.CloneCredential(r.Context(), params)
	if err != nil {
		switch {
		case errors.Is(err, credential.ErrNotFound):
			writeError(w, http.StatusNotFound, "credentials.not_found", "client",
				"source credential not found", false)
		case errors.Is(err, credential.ErrInvalidScope):
			writeError(w, http.StatusBadRequest, "credentials.invalid_scope", "client",
				"scope and scope_id mismatch", false)
		case errors.Is(err, credential.ErrMultipleSystemDefaults):
			writeError(w, http.StatusConflict, "credentials.multiple_system_defaults", "client",
				"another system default already exists", false)
		default:
			writeError(w, http.StatusInternalServerError, "server.error", "server",
				err.Error(), true)
		}
		return
	}
	emitAudit(r, audit.CredentialCreated, newID.String(), map[string]any{
		"credential_id": newID.String(),
		"cloned_from":   uuid.UUID(srcID).String(),
		"scope":         string(params.Scope),
	})

	created, err := h.credentials.GetMetadataByID(r.Context(), newID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server.error", "server",
			"clone succeeded but lookup failed", true)
		return
	}
	writeJSON(w, http.StatusCreated, credentialResponse(created))
}

// DeleteCredentialByID soft-deletes a credential.
// Spec api-credentials AC-09.
func (h *handlers) DeleteCredentialByID(w http.ResponseWriter, r *http.Request, id openapitypes.UUID) {
	if denied := auth.EnforcePermission(w, r, auth.CredentialDelete); denied {
		return
	}
	if err := h.credentials.SoftDelete(r.Context(), uuid.UUID(id)); err != nil {
		if errors.Is(err, credential.ErrNotFound) {
			writeError(w, http.StatusNotFound, "credentials.not_found", "client",
				"credential not found", false)
			return
		}
		writeError(w, http.StatusInternalServerError, "server.error", "server",
			"delete failed", true)
		return
	}
	emitAudit(r, audit.CredentialDeleted, id.String(), map[string]any{
		"credential_id": id.String(),
	})
	w.WriteHeader(http.StatusNoContent)
}

// PostHostCredentialsResolve returns the metadata of the credential
// that would be used for the given host (host-scope first, then system
// default).
// Spec api-credentials AC-10, AC-11, AC-12.
func (h *handlers) PostHostCredentialsResolve(w http.ResponseWriter, r *http.Request, hostID openapitypes.UUID) {
	if denied := auth.EnforcePermission(w, r, auth.CredentialRead); denied {
		return
	}
	m, err := h.credentials.ResolveMetadata(r.Context(), uuid.UUID(hostID))
	if err != nil {
		if errors.Is(err, credential.ErrNoCredential) {
			writeError(w, http.StatusNotFound, "credentials.none_available", "client",
				"no credential available for host or system default", false)
			return
		}
		writeError(w, http.StatusInternalServerError, "server.error", "server",
			"resolve failed", true)
		return
	}
	writeJSON(w, http.StatusOK, credentialResponse(m))
}

// credentialParamsFromRequest validates and translates the wire shape
// into the credential.NewParams the service consumes. Validation here
// is strictly shape-level; semantic checks (scope/scope_id consistency,
// required secrets per auth_method) are enforced by the service.
func credentialParamsFromRequest(r *http.Request, req api.CredentialCreateRequest, creator *uuid.UUID) (credential.NewParams, error) {
	var scopeID *uuid.UUID
	if req.ScopeId != nil {
		u := uuid.UUID(*req.ScopeId)
		scopeID = &u
	}
	createdBy := uuid.Nil
	if creator != nil {
		createdBy = *creator
	}
	params := credential.NewParams{
		Scope:      credential.Scope(req.Scope),
		ScopeID:    scopeID,
		Name:       req.Name,
		Username:   req.Username,
		AuthMethod: credential.AuthMethod(req.AuthMethod),
		CreatedBy:  createdBy,
	}
	if req.Description != nil {
		params.Description = *req.Description
	}
	if req.Password != nil {
		params.Password = *req.Password
	}
	if req.PrivateKey != nil {
		params.PrivateKey = *req.PrivateKey
	}
	if req.PrivateKeyPassphrase != nil {
		params.PrivateKeyPassphrase = *req.PrivateKeyPassphrase
	}
	if req.IsDefault != nil {
		params.IsDefault = *req.IsDefault
	}
	return params, nil
}

// credentialResponse maps credential.Metadata into the wire shape. Note
// the absence of any secret-bearing field — that's the C-01 invariant.
func credentialResponse(m credential.Metadata) api.CredentialResponse {
	var scopeID *openapitypes.UUID
	if m.ScopeID != nil {
		u := openapitypes.UUID(*m.ScopeID)
		scopeID = &u
	}
	createdBy := openapitypes.UUID(m.CreatedBy)
	desc := m.Description
	fp := m.SSHKeyFingerprint
	kt := m.SSHKeyType
	bits := m.SSHKeyBits
	comment := m.SSHKeyComment
	return api.CredentialResponse{
		Id:                openapitypes.UUID(m.ID),
		Scope:             api.CredentialResponseScope(m.Scope),
		ScopeId:           scopeID,
		Name:              m.Name,
		Description:       &desc,
		Username:          m.Username,
		AuthMethod:        api.CredentialResponseAuthMethod(m.AuthMethod),
		SshKeyFingerprint: &fp,
		SshKeyType:        &kt,
		SshKeyBits:        &bits,
		SshKeyComment:     &comment,
		IsDefault:         m.IsDefault,
		IsActive:          m.IsActive,
		CreatedBy:         &createdBy,
		CreatedAt:         &m.CreatedAt,
		UpdatedAt:         &m.UpdatedAt,
	}
}
