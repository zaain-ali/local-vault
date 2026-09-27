package api

import (
	"fmt"
	"net/http"
	"time"
)

type JoinResponse struct {
	VaultID     string `json:"vault_id"`
	WorkspaceID string `json:"workspace_id"`
	Snapshot    []byte `json:"snapshot"`
	Peers       []Peer `json:"peers"`
	WrappedDEK  []byte `json:"wrapped_dek"`
	Message     string `json:"message,omitempty"`
}

type SendMessageRequest struct {
	ForDeviceID   string `json:"for_device_id"`
	FromDeviceID  string `json:"from_device_id"`
	FromPublicKey []byte `json:"from_public_key"`
	Payload       []byte `json:"payload"`
}

type PendingMessage struct {
	ID            string    `json:"id"`
	ForDeviceID   string    `json:"for_device_id"`
	FromDeviceID  string    `json:"from_device_id"`
	FromPublicKey []byte    `json:"from_public_key"`
	Payload       []byte    `json:"payload"`
	CreatedAt     time.Time `json:"created_at"`
}

type MessagesResponse struct {
	Messages []PendingMessage `json:"messages"`
	Count    int              `json:"count"`
}

func (c *Client) SendMessage(req SendMessageRequest) error {
	return c.do(http.MethodPost, "/api/v1/messages", req, nil, true)
}

func (c *Client) GetMessages(deviceID string) (*MessagesResponse, error) {
	var out MessagesResponse
	path := fmt.Sprintf("/api/v1/messages/%s", deviceID)
	if err := c.do(http.MethodGet, path, nil, &out, true); err != nil {
		return nil, err
	}
	return &out, nil
}
