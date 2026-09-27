package dashboard

import (
	"context"
	"time"

	"github.com/zain-23/local-vault/apps/server/internal/audit"
	"github.com/zain-23/local-vault/apps/server/internal/common/apperror"
)

const recentEventLimit = 10

type Service struct {
	store *Store
}

func NewService(store *Store) *Service {
	return &Service{store: store}
}

// Summary returns workspace overview counts.
func (s *Service) Summary(ctx context.Context, workspaceID string) (*SummaryResponse, error) {
	counts, err := s.store.GetSummaryCounts(ctx, workspaceID)
	if err != nil {
		return nil, apperror.ErrInternal
	}
	return &SummaryResponse{
		Vaults: VaultCounts{
			Total:        counts.Vaults.Total,
			WithSnapshot: counts.Vaults.WithSnapshot,
			MemberTotal:  counts.VaultMemberTotal,
		},
		Members:       CountTotal{Total: counts.MemberTotal},
		Invites:       CountPending{Pending: counts.PendingInvites},
		Collaborators: CountPending{Pending: counts.PendingCollaborators},
	}, nil
}

// Activity returns recent events and a daily series for the requested range.
func (s *Service) Activity(ctx context.Context, workspaceID string, q ActivityQuery) (*ActivityResponse, error) {
	rangeKey, days, err := parseRange(q.Range)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	// Start of today UTC, then subtract (days-1) so the window includes today.
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	from := today.AddDate(0, 0, -(days - 1))

	recent, err := s.store.ListRecentEvents(ctx, workspaceID, from, recentEventLimit)
	if err != nil {
		return nil, apperror.ErrInternal
	}
	if recent == nil {
		recent = []audit.EventResponse{}
	}

	rows, err := s.store.AggregateSeries(ctx, workspaceID, from)
	if err != nil {
		return nil, apperror.ErrInternal
	}

	return &ActivityResponse{
		Range:  rangeKey,
		Recent: recent,
		Series: fillSeries(from, days, rows),
	}, nil
}

// parseRange returns the canonical range key and number of days. Empty defaults to 1y.
func parseRange(raw string) (string, int, error) {
	switch raw {
	case "", "1y", "365d":
		return "1y", 365, nil
	case "7d":
		return "7d", 7, nil
	case "30d":
		return "30d", 30, nil
	default:
		return "", 0, apperror.New(400, "range must be 1y, 7d, or 30d")
	}
}

// fillSeries builds one SeriesPoint per UTC day from from (inclusive) for days days.
func fillSeries(from time.Time, days int, rows []seriesRow) []SeriesPoint {
	byDay := make(map[string]map[string]int64, days)
	for _, r := range rows {
		day := r.ID.Date.UTC().Format("2006-01-02")
		if byDay[day] == nil {
			byDay[day] = make(map[string]int64)
		}
		prefix := r.ID.Prefix
		if prefix == "" {
			prefix = "unknown"
		}
		byDay[day][prefix] += r.Count
	}

	out := make([]SeriesPoint, 0, days)
	for i := 0; i < days; i++ {
		day := from.AddDate(0, 0, i).Format("2006-01-02")
		prefixes := byDay[day]
		if prefixes == nil {
			prefixes = map[string]int64{}
		}
		var total int64
		for _, n := range prefixes {
			total += n
		}
		out = append(out, SeriesPoint{
			Date:     day,
			Total:    total,
			ByPrefix: prefixes,
		})
	}
	return out
}
