package server

import (
	"errors"
	"net/http"

	"github.com/Hanalyx/openwatch/internal/server/api"
)

// requestErrorHandler turns the generated router's parameter-binding
// failures into the canonical envelope. The generator's default answers
// text/plain with the parser's own error text, which repeats the rejected
// value back to the client. The envelope names the parameter and nothing
// else: the value is the client's own input and the parser's wording is
// internal detail. Spec: system-http-server C-15.
func requestErrorHandler(w http.ResponseWriter, _ *http.Request, err error) {
	var (
		required  *api.RequiredParamError
		reqHeader *api.RequiredHeaderError
		format    *api.InvalidParamFormatError
		tooMany   *api.TooManyValuesForParamError
		cookie    *api.UnescapedCookieParamError
		unmarshal *api.UnmarshalingParamError
	)
	switch {
	case errors.As(err, &required):
		writeError(w, http.StatusBadRequest, "request.missing_parameter", "client",
			"parameter "+required.ParamName+" is required", false)
	case errors.As(err, &reqHeader):
		writeError(w, http.StatusBadRequest, "request.missing_parameter", "client",
			"header "+reqHeader.ParamName+" is required", false)
	case errors.As(err, &format):
		writeError(w, http.StatusBadRequest, "request.invalid_parameter", "client",
			"parameter "+format.ParamName+" is not valid", false)
	case errors.As(err, &tooMany):
		writeError(w, http.StatusBadRequest, "request.invalid_parameter", "client",
			"parameter "+tooMany.ParamName+" was given more than once", false)
	case errors.As(err, &cookie):
		writeError(w, http.StatusBadRequest, "request.invalid_parameter", "client",
			"cookie "+cookie.ParamName+" is not valid", false)
	case errors.As(err, &unmarshal):
		writeError(w, http.StatusBadRequest, "request.invalid_parameter", "client",
			"parameter "+unmarshal.ParamName+" is not valid", false)
	default:
		writeError(w, http.StatusBadRequest, "request.invalid", "client",
			"the request could not be parsed", false)
	}
}

// writeNotFound is the envelope for an /api/ path no route matches.
func writeNotFound(w http.ResponseWriter) {
	writeError(w, http.StatusNotFound, "request.not_found", "client",
		"no such API route", false)
}

// writeMethodNotAllowed is the envelope for a route that does not accept
// the request's method.
func writeMethodNotAllowed(w http.ResponseWriter) {
	writeError(w, http.StatusMethodNotAllowed, "request.method_not_allowed", "client",
		"the route does not accept this method", false)
}
