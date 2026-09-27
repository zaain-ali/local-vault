// Mirrors server/internal/dashboard/dto.go

import type { AuditEvent } from "#/features/audit/api";

export interface VaultCounts {
	total: number;
	with_snapshot: number;
	/** Vault memberships across the workspace, not distinct people. */
	member_total: number;
}

export interface CountTotal {
	total: number;
}

export interface CountPending {
	pending: number;
}

export interface DashboardSummary {
	vaults: VaultCounts;
	members: CountTotal;
	invites: CountPending;
	collaborators: CountPending;
}

export type ActivityRange = "1y" | "7d" | "30d";

export interface SeriesPoint {
	date: string;
	total: number;
	by_prefix: Record<string, number>;
}

export interface DashboardActivity {
	range: ActivityRange;
	recent: AuditEvent[];
	series: SeriesPoint[];
}

export interface ActivityParams {
	range?: ActivityRange;
}
