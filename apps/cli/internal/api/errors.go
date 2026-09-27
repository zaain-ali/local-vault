package api

import "errors"

// ErrNotLoggedIn is returned when there is no usable session (and refresh failed).
var ErrNotLoggedIn = errors.New("session expired — run: lv login")

// ErrNotModified is returned when If-None-Match matches the current ETag.
var ErrNotModified = errors.New("not modified")

// APIError carries the server's error message, HTTP status and optional code.
type APIError struct {
	Status       int
	Message      string
	Code         string
	HeadRevision int
}

func (e *APIError) Error() string { return e.Message }

func IsCode(err error, code string) bool {
	var ae *APIError
	return errors.As(err, &ae) && ae.Code == code
}
