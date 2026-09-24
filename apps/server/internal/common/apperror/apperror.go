package apperror

import "fmt"

type Error struct {
	Status  int            // HTTP status: 400, 401, 404, 500 etc.
	Message string         // sent to client as {"error": "message"}
	Code    string         // optional machine code, sent as {"code": "..."}
	Extra   map[string]any // optional extra top-level fields (e.g. head_revision, missing)
}

// Error() makes this type satisfy Go's error interface — any type with Error() string is an "error"
func (e *Error) Error() string {
	return fmt.Sprintf("%d: %s", e.Status, e.Message)
}

// New creates an error with status + message — use in services to signal HTTP errors
func New(status int, message string) *Error {
	return &Error{Status: status, Message: message}
}

// WithCode creates an error that also carries a machine-readable code.
func WithCode(status int, code, message string) *Error {
	return &Error{Status: status, Code: code, Message: message}
}

// With returns a copy of e with one extra body field set — never mutates shared errors.
func (e *Error) With(key string, value any) *Error {
	cp := *e
	cp.Extra = make(map[string]any, len(e.Extra)+1)
	for k, v := range e.Extra {
		cp.Extra[k] = v
	}
	cp.Extra[key] = value
	return &cp
}

// Body is the JSON error envelope: {"error": msg, "code": code?, ...extra}.
// "error" and "code" always win over an Extra key of the same name.
func (e *Error) Body() map[string]any {
	body := make(map[string]any, len(e.Extra)+2)
	for k, v := range e.Extra {
		body[k] = v
	}
	body["error"] = e.Message
	if e.Code != "" {
		body["code"] = e.Code
	} else {
		delete(body, "code")
	}
	return body
}

// Pre-built errors — reuse these instead of creating new ones each time
var (
	ErrBadRequest   = New(400, "bad request")
	ErrInvalidBody  = New(400, "invalid request body")
	ErrUnauthorized = New(401, "unauthorized")
	ErrForbidden    = New(403, "forbidden")
	ErrNotFound     = New(404, "not found")
	ErrConflict     = New(409, "already exists")
	ErrInternal     = New(500, "internal server error")
)
