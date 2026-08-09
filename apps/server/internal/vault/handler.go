package vault

import (
	"github.com/gofiber/fiber/v2"

	"github.com/zain-23/local-vault/apps/server/internal/common/apperror"
	"github.com/zain-23/local-vault/apps/server/internal/common/middleware"
	"github.com/zain-23/local-vault/apps/server/internal/common/response"
	"github.com/zain-23/local-vault/apps/server/internal/common/validate"
)

type Handler struct {
	svc *Service
}

func NewHandler(svc *Service) *Handler {
	return &Handler{svc: svc}
}

// Create — POST /api/v1/workspaces/:wid/vaults
func (h *Handler) Create(c *fiber.Ctx) error {
	var req CreateVaultRequest
	if err := c.BodyParser(&req); err != nil {
		return apperror.ErrInvalidBody
	}
	if msg := validate.Struct(req); msg != "" {
		return apperror.New(400, msg)
	}
	user := middleware.GetUser(c)
	res, err := h.svc.Create(c.UserContext(), c.Params("wid"), user.ID, req)
	if err != nil {
		return err
	}
	return response.Success(c, res, fiber.StatusCreated, "vault created")
}

// List — GET /api/v1/workspaces/:wid/vaults
func (h *Handler) List(c *fiber.Ctx) error {
	res, err := h.svc.List(c.UserContext(), c.Params("wid"))
	if err != nil {
		return err
	}
	return response.Success(c, res, fiber.StatusOK, "vaults retrieved")
}

// Get — GET /api/v1/workspaces/:wid/vaults/:id
func (h *Handler) Get(c *fiber.Ctx) error {
	res, err := h.svc.Get(c.UserContext(), c.Params("wid"), c.Params("id"))
	if err != nil {
		return err
	}
	return response.Success(c, res, fiber.StatusOK, "vault retrieved")
}

// Delete — DELETE /api/v1/workspaces/:wid/vaults/:id
func (h *Handler) Delete(c *fiber.Ctx) error {
	if err := h.svc.Delete(c.UserContext(), c.Params("wid"), c.Params("id")); err != nil {
		return err
	}
	return response.Success(c, nil, fiber.StatusOK, "vault deleted")
}

// PushSnapshot — PUT /api/v1/workspaces/:wid/vaults/:id/snapshot
func (h *Handler) PushSnapshot(c *fiber.Ctx) error {
	var req PushSnapshotRequest
	if err := c.BodyParser(&req); err != nil {
		return apperror.ErrInvalidBody
	}
	if msg := validate.Struct(req); msg != "" {
		return apperror.New(400, msg)
	}
	res, err := h.svc.PushSnapshot(c.UserContext(), c.Params("wid"), c.Params("id"), req.DeviceID, req.Snapshot)
	if err != nil {
		return err
	}
	return response.Success(c, res, fiber.StatusOK, "snapshot updated")
}

// PullSnapshot — GET /api/v1/workspaces/:wid/vaults/:id/snapshot
func (h *Handler) PullSnapshot(c *fiber.Ctx) error {
	res, err := h.svc.PullSnapshot(c.UserContext(), c.Params("wid"), c.Params("id"), c.Get("X-Device-ID"))
	if err != nil {
		return err
	}
	return response.Success(c, res, fiber.StatusOK, "snapshot retrieved")
}

// CreateToken — POST /api/v1/workspaces/:wid/vaults/:id/tokens
func (h *Handler) CreateToken(c *fiber.Ctx) error {
	var req CreateTokenRequest
	if err := c.BodyParser(&req); err != nil {
		return apperror.ErrInvalidBody
	}
	if msg := validate.Struct(req); msg != "" {
		return apperror.New(400, msg)
	}
	res, err := h.svc.CreateToken(c.UserContext(), c.Params("wid"), c.Params("id"), req)
	if err != nil {
		return err
	}
	return response.Success(c, res, fiber.StatusCreated, "token created")
}

// ListTokens — GET /api/v1/workspaces/:wid/vaults/:id/tokens
func (h *Handler) ListTokens(c *fiber.Ctx) error {
	res, err := h.svc.ListTokens(c.UserContext(), c.Params("wid"), c.Params("id"))
	if err != nil {
		return err
	}
	return response.Success(c, res, fiber.StatusOK, "tokens retrieved")
}

// RevokeToken — DELETE /api/v1/workspaces/:wid/vaults/:id/tokens/:tid
func (h *Handler) RevokeToken(c *fiber.Ctx) error {
	if err := h.svc.RevokeToken(c.UserContext(), c.Params("wid"), c.Params("id"), c.Params("tid")); err != nil {
		return err
	}
	return response.Success(c, nil, fiber.StatusOK, "token revoked")
}

// RemovePeer — DELETE /api/v1/workspaces/:wid/vaults/:id/peers/:did
func (h *Handler) RemovePeer(c *fiber.Ctx) error {
	if err := h.svc.RemovePeer(c.UserContext(), c.Params("wid"), c.Params("id"), c.Params("did")); err != nil {
		return err
	}
	return response.Success(c, nil, fiber.StatusOK, "peer removed")
}

// InviteCollaborator — POST .../vaults/:id/collaborators
func (h *Handler) InviteCollaborator(c *fiber.Ctx) error {
	var req InviteCollaboratorRequest
	if err := c.BodyParser(&req); err != nil {
		return apperror.ErrInvalidBody
	}
	if msg := validate.Struct(req); msg != "" {
		return apperror.New(400, msg)
	}
	user := middleware.GetUser(c)
	res, err := h.svc.InviteCollaborator(c.UserContext(), c.Params("wid"), c.Params("id"), user.ID, req)
	if err != nil {
		return err
	}
	return response.Success(c, res, fiber.StatusCreated, "collaborator invited")
}

// ListCollaborators — GET .../vaults/:id/collaborators
func (h *Handler) ListCollaborators(c *fiber.Ctx) error {
	res, err := h.svc.ListCollaborators(c.UserContext(), c.Params("wid"), c.Params("id"))
	if err != nil {
		return err
	}
	return response.Success(c, res, fiber.StatusOK, "collaborators retrieved")
}

// RevokeCollaborator — DELETE .../vaults/:id/collaborators/:cid
func (h *Handler) RevokeCollaborator(c *fiber.Ctx) error {
	if err := h.svc.RevokeCollaborator(c.UserContext(), c.Params("wid"), c.Params("id"), c.Params("cid")); err != nil {
		return err
	}
	return response.Success(c, nil, fiber.StatusOK, "invite revoked")
}

// JoinByCode — POST /api/v1/join-code
func (h *Handler) JoinByCode(c *fiber.Ctx) error {
	var req JoinByCodeRequest
	if err := c.BodyParser(&req); err != nil {
		return apperror.ErrInvalidBody
	}
	if msg := validate.Struct(req); msg != "" {
		return apperror.New(400, msg)
	}
	user := middleware.GetUser(c)
	res, err := h.svc.JoinByCode(c.UserContext(), user.ID, user.Email, req)
	if err != nil {
		return err
	}
	return response.Success(c, res, fiber.StatusOK, "joined vault")
}

// Join — POST /api/v1/join (legacy token join).
func (h *Handler) Join(c *fiber.Ctx) error {
	var req JoinRequest
	if err := c.BodyParser(&req); err != nil {
		return apperror.ErrInvalidBody
	}
	if msg := validate.Struct(req); msg != "" {
		return apperror.New(400, msg)
	}
	user := middleware.GetUser(c)
	res, err := h.svc.Join(c.UserContext(), req, user.ID)
	if err != nil {
		return err
	}
	return response.Success(c, res, fiber.StatusOK, "joined vault")
}

// SendMessage — POST /api/v1/messages (auth required).
func (h *Handler) SendMessage(c *fiber.Ctx) error {
	var req SendMessageRequest
	if err := c.BodyParser(&req); err != nil {
		return apperror.ErrInvalidBody
	}
	if msg := validate.Struct(req); msg != "" {
		return apperror.New(400, msg)
	}
	res, err := h.svc.SendMessage(c.UserContext(), req)
	if err != nil {
		return err
	}
	return response.Success(c, res, fiber.StatusCreated, "message queued")
}

// GetMessages — GET /api/v1/messages/:deviceId (auth required).
func (h *Handler) GetMessages(c *fiber.Ctx) error {
	res, err := h.svc.GetMessages(c.UserContext(), c.Params("deviceId"))
	if err != nil {
		return err
	}
	return response.Success(c, res, fiber.StatusOK, "messages retrieved")
}
