package machine

import (
	"fmt"

	"github.com/gofiber/fiber/v2"

	"github.com/zain-23/local-vault/apps/server/internal/common/apperror"
	"github.com/zain-23/local-vault/apps/server/internal/common/middleware"
	"github.com/zain-23/local-vault/apps/server/internal/common/response"
	"github.com/zain-23/local-vault/apps/server/internal/common/validate"
	"github.com/zain-23/local-vault/apps/server/internal/events"
)

type Handler struct {
	svc *Service
	hub *events.Hub
}

func NewHandler(svc *Service, hub *events.Hub) *Handler {
	return &Handler{svc: svc, hub: hub}
}

func (h *Handler) Create(c *fiber.Ctx) error {
	var req CreateRequest
	if err := c.BodyParser(&req); err != nil {
		return apperror.ErrInvalidBody
	}
	if msg := validate.Struct(req); msg != "" {
		return apperror.New(400, msg)
	}
	user := middleware.GetUser(c)
	res, err := h.svc.Create(c.UserContext(), c.Params("wid"), c.Params("id"), user.ID, user.Email, req)
	if err != nil {
		return err
	}
	return response.Success(c, res, fiber.StatusCreated, "machine created")
}

func (h *Handler) List(c *fiber.Ctx) error {
	user := middleware.GetUser(c)
	res, err := h.svc.List(c.UserContext(), c.Params("wid"), c.Params("id"), user.ID, user.Email)
	if err != nil {
		return err
	}
	return response.Success(c, res, fiber.StatusOK, "machines retrieved")
}

func (h *Handler) Revoke(c *fiber.Ctx) error {
	user := middleware.GetUser(c)
	if err := h.svc.Revoke(c.UserContext(), c.Params("wid"), c.Params("id"), c.Params("mid"), user.ID, user.Email); err != nil {
		return err
	}
	return response.Success(c, nil, fiber.StatusOK, "machine revoked")
}

func (h *Handler) Login(c *fiber.Ctx) error {
	var req LoginRequest
	if err := c.BodyParser(&req); err != nil {
		return apperror.ErrInvalidBody
	}
	if msg := validate.Struct(req); msg != "" {
		return apperror.New(400, msg)
	}
	res, err := h.svc.Login(c.UserContext(), req)
	if err != nil {
		return err
	}
	return response.Success(c, res, fiber.StatusOK, "machine authenticated")
}

func (h *Handler) Secrets(c *fiber.Ctx) error {
	m := middleware.GetMachine(c)
	res, head, err := h.svc.Secrets(c.UserContext(), m.ID, m.WorkspaceID, m.VaultID, m.Env)
	if err != nil {
		return err
	}
	etag := fmt.Sprintf(`"r%d"`, head)
	c.Set("ETag", etag)
	if match := c.Get("If-None-Match"); match == etag {
		return c.SendStatus(fiber.StatusNotModified)
	}
	return response.Success(c, res, fiber.StatusOK, "secrets retrieved")
}

func (h *Handler) Events(c *fiber.Ctx) error {
	m := middleware.GetMachine(c)
	if h.hub == nil {
		return apperror.ErrInternal
	}
	return events.Stream(c, h.hub.Subscribe(m.VaultID), events.StreamOptions{
		Filter: func(e events.Event) bool { return e.Env == "" || e.Env == m.Env },
	})
}

func RegisterRoutes(app *fiber.App, h *Handler, ws middleware.MembershipChecker, userAuth, machineAuth fiber.Handler) {
	v := app.Group("/api/v1/workspaces/:wid/vaults/:id/machines", userAuth)
	member := middleware.RequireRole(ws, "wid", RoleOwner, RoleAdmin, RoleMember)
	v.Post("/", member, h.Create)
	v.Get("/", member, h.List)
	v.Delete("/:mid", member, h.Revoke)

	app.Post("/api/v1/machine/login", h.Login)
	m := app.Group("/api/v1/machine", machineAuth)
	m.Get("/secrets", h.Secrets)
	m.Get("/events", h.Events)
}
