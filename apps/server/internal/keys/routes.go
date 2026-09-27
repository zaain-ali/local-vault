package keys

import (
	"github.com/gofiber/fiber/v2"

	"github.com/zain-23/local-vault/apps/server/internal/common/middleware"
)

// Workspace roles (mirrors member.Role* — duplicated to avoid importing member).
const (
	RoleOwner  = "owner"
	RoleAdmin  = "admin"
	RoleMember = "member"
)

func RegisterRoutes(app *fiber.App, h *Handler, ws middleware.MembershipChecker, authMW fiber.Handler) {
	me := app.Group("/api/v1/keys", authMW)
	me.Get("/me", h.GetMe)
	me.Put("/me", h.PutMe)
	me.Delete("/me", h.DeleteMe)

	app.Get("/api/v1/workspaces/:wid/keys", authMW,
		middleware.RequireRole(ws, "wid", RoleOwner, RoleAdmin, RoleMember), h.WorkspaceKeys)
}
