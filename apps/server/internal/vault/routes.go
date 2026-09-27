package vault

import (
	"github.com/gofiber/fiber/v2"

	"github.com/zain-23/local-vault/apps/server/internal/common/middleware"
)

func RegisterRoutes(app *fiber.App, h *Handler, ws middleware.MembershipChecker, authMW fiber.Handler) {
	v := app.Group("/api/v1/workspaces/:wid/vaults", authMW)
	member := middleware.RequireRole(ws, "wid", RoleOwner, RoleAdmin, RoleMember)

	v.Post("/", member, h.Create)
	v.Get("/", member, h.List)
	v.Get("/:id", member, h.Get)
	v.Delete("/:id", member, h.Delete)

	v.Post("/:id/environments", member, h.AddEnvironment)
	v.Patch("/:id/environments/:env", member, h.PatchEnvironment)

	v.Post("/:id/members", member, h.AddMember)
	v.Patch("/:id/members/:uid", member, h.UpdateMember)
	v.Delete("/:id/members/:uid", member, h.RemoveMember)

	v.Get("/:id/grants/mine", member, h.MyGrants)
	v.Get("/:id/grants/pending", member, h.PendingGrants)
	v.Post("/:id/grants", member, h.CreateGrants)

	v.Get("/:id/environments/:env/head", member, h.Head)
	v.Get("/:id/environments/:env/revisions", member, h.ListRevisions)
	v.Get("/:id/environments/:env/revisions/:rev", member, h.GetRevision)
	v.Post("/:id/environments/:env/revisions", member, h.PushRevision)

	v.Post("/:id/environments/:env/change-requests", member, h.CreateChangeRequest)
	v.Get("/:id/environments/:env/change-requests", member, h.ListChangeRequests)
	v.Post("/:id/environments/:env/change-requests/:crid/approve", member, h.ApproveChangeRequest)
	v.Post("/:id/environments/:env/change-requests/:crid/reject", member, h.RejectChangeRequest)

	v.Post("/:id/environments/:env/rekey", member, h.Rekey)
	v.Get("/:id/events", member, h.Events)
}
