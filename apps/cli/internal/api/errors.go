package api

import "errors"

// ErrNotLoggedIn is returned when there is no usable session (and refresh failed).
var ErrNotLoggedIn = errors.New("session expired — run: lv login")

// APIError carries the server's error message and HTTP status.
type APIError struct {
	Status  int
	Message string
}

func (e *APIError) Error() string { return e.Message }
