package dashboard

import (
	"github.com/zain-23/local-vault/apps/server/internal/audit"
)

// SummaryResponse is the workspace overview payload.
type SummaryResponse struct {
	Vaults        VaultCounts  `json:"vaults"`
	Members       CountTotal   `json:"members"`
	Invites       CountPending `json:"invites"`
	Collaborators CountPending `json:"collaborators"`
}

type VaultCounts struct {
	Total        int64 `json:"total"`
	WithSnapshot int64 `json:"with_snapshot"`
	// MemberTotal counts vault memberships across the workspace (a user in
	// three vaults counts three times), not distinct people.
	MemberTotal int64 `json:"member_total"`
}

type CountTotal struct {
	Total int64 `json:"total"`
}

type CountPending struct {
	Pending int64 `json:"pending"`
}

// ActivityQuery is the GET /dashboard/activity query string.
type ActivityQuery struct {
	Range string `query:"range"` // 7d | 30d; default 7d
}

// ActivityResponse is recent events plus a daily series for the requested range.
type ActivityResponse struct {
	Range  string                `json:"range"`
	Recent []audit.EventResponse `json:"recent"`
	Series []SeriesPoint         `json:"series"`
}

// SeriesPoint is one UTC day bucket of audit activity.
type SeriesPoint struct {
	Date     string           `json:"date"` // YYYY-MM-DD
	Total    int64            `json:"total"`
	ByPrefix map[string]int64 `json:"by_prefix"`
}

// Workspace roles (mirrors other domains — duplicated to avoid importing member).
const (
	RoleOwner  = "owner"
	RoleAdmin  = "admin"
	RoleMember = "member"
)
