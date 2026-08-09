package vault

import (
	"github.com/gofiber/fiber/v2"

	"github.com/zain-23/local-vault/apps/server/internal/common/middleware"
)

func RegisterRoutes(app *fiber.App, h *Handler, ws middleware.MembershipChecker, authMW fiber.Handler) {
	v := app.Group("/api/v1/workspaces/:wid/vaults", authMW)

	member := middleware.RequireRole(ws, "wid", RoleOwner, RoleAdmin, RoleMember)
	admin := middleware.RequireRole(ws, "wid", RoleOwner, RoleAdmin)

	v.Post("/", member, h.Create)
	v.Get("/", member, h.List)
	v.Get("/:id", member, h.Get)
	v.Put("/:id/snapshot", member, h.PushSnapshot)
	v.Get("/:id/snapshot", member, h.PullSnapshot)

	// Legacy join tokens: owner/admin only.
	v.Post("/:id/tokens", admin, h.CreateToken)
	v.Get("/:id/tokens", admin, h.ListTokens)
	v.Delete("/:id/tokens/:tid", admin, h.RevokeToken)

	// Email short-code invites.
	v.Post("/:id/collaborators", admin, h.InviteCollaborator)
	v.Get("/:id/collaborators", admin, h.ListCollaborators)
	v.Delete("/:id/collaborators/:cid", admin, h.RevokeCollaborator)

	v.Delete("/:id", admin, h.Delete)
	v.Delete("/:id/peers/:did", admin, h.RemovePeer)

	// Short-code join (auth required).
	app.Post("/api/v1/join-code", authMW, h.JoinByCode)

	// Legacy token join (auth required).
	app.Post("/api/v1/join", authMW, h.Join)

	msg := app.Group("/api/v1/messages", authMW)
	msg.Post("/", h.SendMessage)
	msg.Get("/:deviceId", h.GetMessages)
}
