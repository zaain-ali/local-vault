package keys

import (
	"github.com/gofiber/fiber/v2"

	"github.com/zain-23/local-vault/apps/server/internal/common/apperror"
	"github.com/zain-23/local-vault/apps/server/internal/common/middleware"
	"github.com/zain-23/local-vault/apps/server/internal/common/response"
)

type Handler struct {
	svc *Service
}

func NewHandler(svc *Service) *Handler {
	return &Handler{svc: svc}
}

// GetMe — GET /api/v1/keys/me
func (h *Handler) GetMe(c *fiber.Ctx) error {
	res, err := h.svc.Me(c.UserContext(), middleware.GetUser(c).ID)
	if err != nil {
		return err
	}
	return response.Success(c, res, fiber.StatusOK, "keys retrieved")
}

// PutMe — PUT /api/v1/keys/me
func (h *Handler) PutMe(c *fiber.Ctx) error {
	var req PutKeysRequest
	if err := c.BodyParser(&req); err != nil {
		return apperror.ErrInvalidBody
	}
	res, err := h.svc.Put(c.UserContext(), middleware.GetUser(c).ID, req)
	if err != nil {
		return err
	}
	return response.Success(c, res, fiber.StatusCreated, "keys stored")
}

// DeleteMe — DELETE /api/v1/keys/me
func (h *Handler) DeleteMe(c *fiber.Ctx) error {
	if err := h.svc.Reset(c.UserContext(), middleware.GetUser(c).ID); err != nil {
		return err
	}
	return response.Success(c, nil, fiber.StatusOK, "keys reset")
}

// WorkspaceKeys — GET /api/v1/workspaces/:wid/keys?user_ids=a,b
func (h *Handler) WorkspaceKeys(c *fiber.Ctx) error {
	res, err := h.svc.WorkspaceKeys(c.UserContext(), c.Params("wid"), c.Query("user_ids"))
	if err != nil {
		return err
	}
	return response.Success(c, res, fiber.StatusOK, "public keys retrieved")
}
