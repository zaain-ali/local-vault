package vault

import (
	"fmt"
	"strconv"
	"strings"

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

func (h *Handler) List(c *fiber.Ctx) error {
	user := middleware.GetUser(c)
	res, err := h.svc.List(c.UserContext(), c.Params("wid"), user.ID)
	if err != nil {
		return err
	}
	return response.Success(c, res, fiber.StatusOK, "vaults retrieved")
}

func (h *Handler) Get(c *fiber.Ctx) error {
	user := middleware.GetUser(c)
	res, err := h.svc.Get(c.UserContext(), c.Params("wid"), c.Params("id"), user.ID, user.Email)
	if err != nil {
		return err
	}
	return response.Success(c, res, fiber.StatusOK, "vault retrieved")
}

func (h *Handler) Delete(c *fiber.Ctx) error {
	user := middleware.GetUser(c)
	if err := h.svc.Delete(c.UserContext(), c.Params("wid"), c.Params("id"), user.ID, user.Email); err != nil {
		return err
	}
	return response.Success(c, nil, fiber.StatusOK, "vault deleted")
}

func (h *Handler) AddEnvironment(c *fiber.Ctx) error {
	var req AddEnvironmentRequest
	if err := c.BodyParser(&req); err != nil {
		return apperror.ErrInvalidBody
	}
	user := middleware.GetUser(c)
	if err := h.svc.AddEnvironment(c.UserContext(), c.Params("wid"), c.Params("id"), user.ID, user.Email, req); err != nil {
		return err
	}
	return response.Success(c, nil, fiber.StatusCreated, "environment added")
}

func (h *Handler) PatchEnvironment(c *fiber.Ctx) error {
	var req PatchEnvironmentRequest
	if err := c.BodyParser(&req); err != nil {
		return apperror.ErrInvalidBody
	}
	user := middleware.GetUser(c)
	if err := h.svc.PatchEnvironment(c.UserContext(), c.Params("wid"), c.Params("id"), c.Params("env"), user.ID, user.Email, req); err != nil {
		return err
	}
	return response.Success(c, nil, fiber.StatusOK, "environment updated")
}

func (h *Handler) AddMember(c *fiber.Ctx) error {
	var req AddMemberRequest
	if err := c.BodyParser(&req); err != nil {
		return apperror.ErrInvalidBody
	}
	if msg := validate.Struct(req); msg != "" {
		return apperror.New(400, msg)
	}
	user := middleware.GetUser(c)
	res, err := h.svc.AddMember(c.UserContext(), c.Params("wid"), c.Params("id"), user.ID, user.Email, req)
	if err != nil {
		return err
	}
	return response.Success(c, res, fiber.StatusCreated, "member added")
}

func (h *Handler) UpdateMember(c *fiber.Ctx) error {
	var req UpdateMemberRequest
	if err := c.BodyParser(&req); err != nil {
		return apperror.ErrInvalidBody
	}
	user := middleware.GetUser(c)
	res, err := h.svc.UpdateMember(c.UserContext(), c.Params("wid"), c.Params("id"), c.Params("uid"), user.ID, user.Email, req)
	if err != nil {
		return err
	}
	return response.Success(c, res, fiber.StatusOK, "member updated")
}

func (h *Handler) RemoveMember(c *fiber.Ctx) error {
	user := middleware.GetUser(c)
	if err := h.svc.RemoveMember(c.UserContext(), c.Params("wid"), c.Params("id"), c.Params("uid"), user.ID, user.Email); err != nil {
		return err
	}
	return response.Success(c, nil, fiber.StatusOK, "member removed")
}

func (h *Handler) MyGrants(c *fiber.Ctx) error {
	user := middleware.GetUser(c)
	res, err := h.svc.MyGrants(c.UserContext(), c.Params("wid"), c.Params("id"), user.ID, user.Email)
	if err != nil {
		return err
	}
	return response.Success(c, res, fiber.StatusOK, "grants retrieved")
}

func (h *Handler) PendingGrants(c *fiber.Ctx) error {
	user := middleware.GetUser(c)
	res, err := h.svc.PendingGrants(c.UserContext(), c.Params("wid"), c.Params("id"), user.ID, user.Email)
	if err != nil {
		return err
	}
	return response.Success(c, res, fiber.StatusOK, "pending grants retrieved")
}

func (h *Handler) CreateGrants(c *fiber.Ctx) error {
	var req CreateGrantsRequest
	if err := c.BodyParser(&req); err != nil {
		return apperror.ErrInvalidBody
	}
	user := middleware.GetUser(c)
	if err := h.svc.CreateGrants(c.UserContext(), c.Params("wid"), c.Params("id"), user.ID, user.Email, req); err != nil {
		return err
	}
	return response.Success(c, nil, fiber.StatusCreated, "grants stored")
}

func (h *Handler) Head(c *fiber.Ctx) error {
	user := middleware.GetUser(c)
	res, err := h.svc.Head(c.UserContext(), c.Params("wid"), c.Params("id"), c.Params("env"), user.ID, user.Email)
	if err != nil {
		return err
	}
	etag := fmt.Sprintf(`"r%d"`, res.Revision)
	c.Set("ETag", etag)
	if match := c.Get("If-None-Match"); match != "" && etagEqual(match, etag) {
		return c.SendStatus(fiber.StatusNotModified)
	}
	return response.Success(c, res, fiber.StatusOK, "head retrieved")
}

func (h *Handler) ListRevisions(c *fiber.Ctx) error {
	user := middleware.GetUser(c)
	before, _ := strconv.Atoi(c.Query("before"))
	limit, _ := strconv.Atoi(c.Query("limit"))
	res, err := h.svc.ListRevisions(c.UserContext(), c.Params("wid"), c.Params("id"), c.Params("env"), user.ID, user.Email, before, limit)
	if err != nil {
		return err
	}
	return response.Success(c, res, fiber.StatusOK, "revisions retrieved")
}

func (h *Handler) GetRevision(c *fiber.Ctx) error {
	rev, err := strconv.Atoi(c.Params("rev"))
	if err != nil || rev < 1 {
		return apperror.New(400, "invalid revision")
	}
	user := middleware.GetUser(c)
	res, err := h.svc.GetRevision(c.UserContext(), c.Params("wid"), c.Params("id"), c.Params("env"), rev, user.ID, user.Email)
	if err != nil {
		return err
	}
	return response.Success(c, res, fiber.StatusOK, "revision retrieved")
}

func (h *Handler) PushRevision(c *fiber.Ctx) error {
	var req PushRevisionRequest
	if err := c.BodyParser(&req); err != nil {
		return apperror.ErrInvalidBody
	}
	user := middleware.GetUser(c)
	res, err := h.svc.PushRevision(c.UserContext(), c.Params("wid"), c.Params("id"), c.Params("env"), user.ID, user.Email, c.Get("Idempotency-Key"), req)
	if err != nil {
		return err
	}
	return response.Success(c, res, fiber.StatusCreated, "revision committed")
}

func (h *Handler) CreateChangeRequest(c *fiber.Ctx) error {
	var req CreateChangeRequestBody
	if err := c.BodyParser(&req); err != nil {
		return apperror.ErrInvalidBody
	}
	user := middleware.GetUser(c)
	res, err := h.svc.CreateChangeRequest(c.UserContext(), c.Params("wid"), c.Params("id"), c.Params("env"), user.ID, user.Email, req)
	if err != nil {
		return err
	}
	return response.Success(c, res, fiber.StatusCreated, "change request created")
}

func (h *Handler) ListChangeRequests(c *fiber.Ctx) error {
	user := middleware.GetUser(c)
	res, err := h.svc.ListChangeRequests(c.UserContext(), c.Params("wid"), c.Params("id"), c.Params("env"), c.Query("status"), user.ID, user.Email)
	if err != nil {
		return err
	}
	return response.Success(c, res, fiber.StatusOK, "change requests retrieved")
}

func (h *Handler) ApproveChangeRequest(c *fiber.Ctx) error {
	user := middleware.GetUser(c)
	res, err := h.svc.ApproveChangeRequest(c.UserContext(), c.Params("wid"), c.Params("id"), c.Params("env"), c.Params("crid"), user.ID, user.Email)
	if err != nil {
		return err
	}
	return response.Success(c, res, fiber.StatusOK, "change request approved")
}

func (h *Handler) RejectChangeRequest(c *fiber.Ctx) error {
	user := middleware.GetUser(c)
	if err := h.svc.RejectChangeRequest(c.UserContext(), c.Params("wid"), c.Params("id"), c.Params("env"), c.Params("crid"), user.ID, user.Email); err != nil {
		return err
	}
	return response.Success(c, nil, fiber.StatusOK, "change request rejected")
}

func (h *Handler) Rekey(c *fiber.Ctx) error {
	var req RekeyRequest
	if err := c.BodyParser(&req); err != nil {
		return apperror.ErrInvalidBody
	}
	user := middleware.GetUser(c)
	res, err := h.svc.Rekey(c.UserContext(), c.Params("wid"), c.Params("id"), c.Params("env"), user.ID, user.Email, req)
	if err != nil {
		return err
	}
	return response.Success(c, res, fiber.StatusOK, "environment rekeyed")
}

func (h *Handler) Events(c *fiber.Ctx) error {
	user := middleware.GetUser(c)
	if _, err := h.svc.resolve(c.UserContext(), c.Params("wid"), c.Params("id"), user.ID, user.Email); err != nil {
		return err
	}
	if h.hub == nil {
		return apperror.ErrInternal
	}
	return events.Stream(c, h.hub.Subscribe(c.Params("id")), events.StreamOptions{})
}

func etagEqual(got, want string) bool {
	got = strings.TrimSpace(got)
	if strings.HasPrefix(got, "W/") {
		got = strings.TrimSpace(got[2:])
	}
	return got == want
}
