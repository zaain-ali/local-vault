import { Skeleton } from "#/components/ui";
import type { DashboardSummary } from "#/features/dashboard/api";

type SummaryStatsProps = {
	summary: DashboardSummary | undefined;
	isLoading: boolean;
};

type Stat = {
	label: string;
	value: string;
	hint?: string;
};

function buildStats(summary: DashboardSummary): Stat[] {
	const { vaults, members, invites, collaborators } = summary;
	const pending = invites.pending + collaborators.pending;

	return [
		{
			label: "Vaults",
			value: String(vaults.total),
			hint:
				vaults.total === 0
					? undefined
					: `${vaults.with_snapshot} with snapshot`,
		},
		{
			label: "Vault members",
			value: String(vaults.member_total),
		},
		{
			label: "Members",
			value: String(members.total),
		},
		{
			label: "Pending invites",
			value: String(pending),
			hint:
				pending === 0
					? undefined
					: `${invites.pending} workspace · ${collaborators.pending} vault`,
		},
	];
}

export function SummaryStats({ summary, isLoading }: SummaryStatsProps) {
	if (isLoading || !summary) {
		return (
			<section className="grid grid-cols-2 gap-3 sm:grid-cols-4">
				{(["s1", "s2", "s3", "s4"] as const).map((key) => (
					<div
						key={key}
						className="space-y-2 rounded-lg border border-border bg-background p-4"
					>
						<Skeleton className="h-3 w-16" />
						<Skeleton className="h-7 w-10" />
					</div>
				))}
			</section>
		);
	}

	const stats = buildStats(summary);

	return (
		<section className="grid grid-cols-2 gap-3 sm:grid-cols-4">
			{stats.map((stat) => (
				<div
					key={stat.label}
					className="rounded-lg border border-border bg-background p-4"
				>
					<p className="text-sm text-muted-foreground">{stat.label}</p>
					<p className="mt-1 text-2xl font-semibold tracking-tight tabular-nums">
						{stat.value}
					</p>
					{stat.hint ? (
						<p className="mt-1 text-xs text-muted-foreground">{stat.hint}</p>
					) : null}
				</div>
			))}
		</section>
	);
}
