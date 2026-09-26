package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/zain-23/local-vault/apps/cli/internal/authstore"
)

// Client talks to the /api/v1 server with automatic auth + one-shot refresh.
type Client struct {
	baseURL string
	http    *http.Client
	tokens  *authstore.Tokens
}

func New(baseURL string) *Client {
	return &Client{
		baseURL: baseURL,
		http:    &http.Client{Timeout: 30 * time.Second},
	}
}

// UseTokens injects tokens so the client skips a keychain read.
func (c *Client) UseTokens(t *authstore.Tokens) { c.tokens = t }

// envelope mirrors server/internal/common/response.Envelope.
type envelope struct {
	Data    json.RawMessage `json:"data"`
	Success bool            `json:"success"`
	Message string          `json:"message"`
	Status  int             `json:"status"`
}

type errorBody struct {
	Error        string `json:"error"`
	Code         string `json:"code"`
	HeadRevision int    `json:"head_revision"`
}

// do performs a request. When authed, it attaches the bearer token and, on 401,
// refreshes once and retries.
func (c *Client) do(method, path string, body, out any, authed bool) error {
	return c.doWithHeaders(method, path, body, out, authed, nil)
}

func (c *Client) doWithHeaders(method, path string, body, out any, authed bool, headers map[string]string) error {
	status, respBody, err := c.send(method, path, body, authed, headers)
	if err != nil {
		return err
	}

	if authed && status == http.StatusUnauthorized {
		if rerr := c.refresh(); rerr != nil {
			_ = authstore.Clear()
			return ErrNotLoggedIn
		}
		status, respBody, err = c.send(method, path, body, authed, headers)
		if err != nil {
			return err
		}
	}

	if status == http.StatusNotModified {
		return ErrNotModified
	}
	if status >= 400 {
		var eb errorBody
		_ = json.Unmarshal(respBody, &eb)
		msg := eb.Error
		if msg == "" {
			msg = fmt.Sprintf("server error (status %d)", status)
		}
		return &APIError{Status: status, Message: msg, Code: eb.Code, HeadRevision: eb.HeadRevision}
	}

	if out != nil {
		var env envelope
		if err := json.Unmarshal(respBody, &env); err != nil {
			return fmt.Errorf("invalid server response: %w", err)
		}
		if len(env.Data) == 0 || string(env.Data) == "null" {
			return nil
		}
		if err := json.Unmarshal(env.Data, out); err != nil {
			return fmt.Errorf("invalid server response data: %w", err)
		}
	}
	return nil
}

// send issues one HTTP request and returns status + body.
func (c *Client) send(method, path string, body any, authed bool, headers map[string]string) (int, []byte, error) {
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return 0, nil, err
		}
		reader = bytes.NewReader(data)
	}

	req, err := http.NewRequest(method, c.baseURL+path, reader)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	if authed {
		tok, err := c.currentTokens()
		if err != nil {
			return 0, nil, ErrNotLoggedIn
		}
		req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("cannot reach server at %s", c.baseURL)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, respBody, nil
}

func (c *Client) currentTokens() (*authstore.Tokens, error) {
	if c.tokens != nil {
		return c.tokens, nil
	}
	t, err := authstore.Load()
	if err != nil {
		return nil, err
	}
	c.tokens = t
	return t, nil
}

// refresh exchanges the refresh token for a fresh access token via the
// device-scoped refresh endpoint (unauthenticated call).
func (c *Client) refresh() error {
	tok, err := c.currentTokens()
	if err != nil {
		return err
	}
	res, err := c.DeviceRefresh(tok.RefreshToken)
	if err != nil {
		return err
	}
	tok.AccessToken = res.AccessToken
	c.tokens = tok
	return authstore.Save(tok)
}
