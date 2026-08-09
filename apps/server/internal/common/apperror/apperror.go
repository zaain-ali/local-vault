package apperror

import "fmt"

type Error struct {
	Status  int    // HTTP status: 400, 401, 404, 500 etc.
	Message string // sent to client as {"error": "message"}
}

// Error() makes this type satisfy Go's error interface — any type with Error() string is an "error"
func (e *Error) Error() string {
	return fmt.Sprintf("%d: %s", e.Status, e.Message)
}

// New creates an error with status + message — use in services to signal HTTP errors
func New(status int, message string) *Error {
	return &Error{Status: status, Message: message}
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