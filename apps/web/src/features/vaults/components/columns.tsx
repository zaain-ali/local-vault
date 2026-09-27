import type { ColumnDef } from "@tanstack/react-table";
import { Vault } from "lucide-react";

import { Badge, Button } from "#/components/ui";
import type {
	ChangeRequest,
	PendingGrant,
	VaultEnvironment,
	VaultMember,
	VaultSummary,
} from "#/features/vaults/api";
import { dateFmt } from "#/lib/utils.ts";

export const vaultColumns: ColumnDef<VaultSummary>[] = [
	{
		accessorKey: "name",
		header: "Name",
		cell: ({ row }) => (
			<div className="flex items-center gap-2.5">
				<Vault className="size-4 shrink-0 text-muted-foreground" />
				<span className="font-mono text-[13.5px] font-medium tracking-tight">
					{row.original.name}
				</span>
			</div>
		),
	},
	{
		accessorKey: "member_count",
		header: "Members",
		size: 100,
		cell: ({ row }) => (
			<span className="font-mono text-sm text-muted-foreground">
				{row.original.member_count}
			</span>
		),
	},
	{
		id: "environments",
		header: "Environments",
		cell: ({ row }) => (
			<span className="text-sm text-muted-foreground">
				{(row.original.environments ?? []).map((e) => e.name).join(", ") || "—"}
			</span>
		),
	},
	{
		accessorKey: "updated_at",
		header: "Updated",
		size: 160,
		cell: ({ row }) => (
			<span className="text-sm text-muted-foreground">
				{dateFmt.format(new Date(row.original.updated_at))}
			</span>
		),
	},
];

export function memberColumns(
	onRemove?: (userId: string) => void,
): ColumnDef<VaultMember>[] {
	return [
		{
			id: "person",
			header: "Person",
			cell: ({ row }) => (
				<div className="flex flex-col gap-0.5">
					<span className="text-sm font-medium">{row.original.name || "—"}</span>
					<span className="text-xs text-muted-foreground">
						{row.original.email}
					</span>
				</div>
			),
		},
		{
			accessorKey: "role",
			header: "Role",
			cell: ({ row }) => (
				<Badge variant="secondary">{row.original.role}</Badge>
			),
		},
		{
			accessorKey: "fingerprint",
			header: "Fingerprint",
			cell: ({ row }) =>
				row.original.fingerprint ? (
					<span className="font-mono text-xs">{row.original.fingerprint}</span>
				) : (
					<Badge variant="outline">No keys yet</Badge>
				),
		},
		{
			id: "actions",
			header: "",
			cell: ({ row }) =>
				onRemove ? (
					<Button
						variant="ghost"
						size="sm"
						onClick={() => onRemove(row.original.user_id)}
					>
						Remove
					</Button>
				) : null,
		},
	];
}

export const grantColumns: ColumnDef<PendingGrant>[] = [
	{
		accessorKey: "label",
		header: "Recipient",
		cell: ({ row }) => (
			<div className="flex flex-col gap-0.5">
				<span className="text-sm font-medium">{row.original.label}</span>
				<span className="text-xs text-muted-foreground">
					{row.original.email || row.original.recipient_type}
				</span>
			</div>
		),
	},
	{
		accessorKey: "env",
		header: "Environment",
		cell: ({ row }) => (
			<span className="font-mono text-[13px]">{row.original.env}</span>
		),
	},
	{
		accessorKey: "fingerprint",
		header: "Fingerprint",
		cell: ({ row }) => (
			<span className="font-mono text-xs">{row.original.fingerprint || "—"}</span>
		),
	},
	{
		accessorKey: "key_type",
		header: "Key",
		cell: ({ row }) => (
			<Badge variant="outline">{row.original.key_type}</Badge>
		),
	},
];

export const environmentColumns: ColumnDef<VaultEnvironment>[] = [
	{
		accessorKey: "name",
		header: "Name",
		cell: ({ row }) => (
			<span className="font-mono text-sm">{row.original.name}</span>
		),
	},
	{
		accessorKey: "head_revision",
		header: "Revision",
		cell: ({ row }) => (
			<span className="font-mono text-sm">{row.original.head_revision}</span>
		),
	},
	{
		accessorKey: "key_version",
		header: "Key",
		cell: ({ row }) => (
			<span className="font-mono text-sm">v{row.original.key_version}</span>
		),
	},
	{
		id: "flags",
		header: "Status",
		cell: ({ row }) => (
			<div className="flex gap-1">
				{row.original.protected ? <Badge variant="secondary">Protected</Badge> : null}
				{row.original.rekey_required ? (
					<Badge variant="destructive">Rekey required</Badge>
				) : null}
			</div>
		),
	},
];

export function changeRequestColumns(
	onReview?: (row: ChangeRequest, action: "approve" | "reject") => void,
): ColumnDef<ChangeRequest>[] {
	return [
		{
			accessorKey: "env",
			header: "Environment",
			cell: ({ row }) => (
				<span className="font-mono text-sm">{row.original.env}</span>
			),
		},
		{
			accessorKey: "note",
			header: "Note",
			cell: ({ row }) => (
				<span className="text-sm">{row.original.note || "—"}</span>
			),
		},
		{
			accessorKey: "created_at",
			header: "Opened",
			cell: ({ row }) => (
				<span className="text-sm text-muted-foreground">
					{dateFmt.format(new Date(row.original.created_at))}
				</span>
			),
		},
		{
			id: "actions",
			header: "",
			cell: ({ row }) =>
				onReview ? (
					<div className="flex gap-2">
						<Button
							size="sm"
							onClick={() => onReview(row.original, "approve")}
						>
							Approve
						</Button>
						<Button
							variant="ghost"
							size="sm"
							onClick={() => onReview(row.original, "reject")}
						>
							Reject
						</Button>
					</div>
				) : null,
		},
	];
}
