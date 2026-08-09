import type { ColumnDef } from "@tanstack/react-table";
import { Vault } from "lucide-react";

import { Badge } from "#/components/ui";
import type {
	VaultCollaborator,
	VaultPeer,
	VaultSummary,
} from "#/features/vaults/api";
import { collaboratorStatusLabel } from "#/features/vaults/utils";
import { dateFmt } from "#/lib/utils.ts";

import { RevokeInviteButton } from "./RevokeInviteButton.tsx";

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
		accessorKey: "peer_count",
		header: "Devices",
		size: 100,
		cell: ({ row }) => (
			<span className="font-mono text-sm text-muted-foreground">
				{row.original.peer_count}
			</span>
		),
	},
	{
		accessorKey: "has_snapshot",
		header: "Snapshot",
		size: 120,
		cell: ({ row }) =>
			row.original.has_snapshot ? (
				<Badge variant="secondary">Yes</Badge>
			) : (
				<Badge variant="outline">No</Badge>
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

export const peerColumns: ColumnDef<VaultPeer>[] = [
	{
		id: "person",
		header: "Person",
		cell: ({ row }) => (
			<div className="flex flex-col gap-0.5">
				<span className="text-sm font-medium">{row.original.name || "—"}</span>
				<span className="text-xs text-muted-foreground">
					{row.original.email || "No account linked"}
				</span>
			</div>
		),
	},
	{
		accessorKey: "device_name",
		header: "Device",
		cell: ({ row }) => (
			<span className="font-mono text-[13px]">{row.original.device_name}</span>
		),
	},
	{
		accessorKey: "device_id",
		header: "Device ID",
		cell: ({ row }) => (
			<span className="font-mono text-xs text-muted-foreground">
				{row.original.device_id.slice(0, 12)}…
			</span>
		),
	},
	{
		accessorKey: "joined_at",
		header: "Joined",
		cell: ({ row }) => (
			<span className="text-sm text-muted-foreground">
				{dateFmt.format(new Date(row.original.joined_at))}
			</span>
		),
	},
];

export const inviteColumns: ColumnDef<VaultCollaborator>[] = [
	{
		accessorKey: "email",
		header: "Email",
		cell: ({ row }) => <span className="text-sm">{row.original.email}</span>,
	},
	{
		accessorKey: "status",
		header: "Status",
		cell: ({ row }) => (
			<Badge variant="secondary">
				{collaboratorStatusLabel(row.original.status)}
			</Badge>
		),
	},
	{
		accessorKey: "created_at",
		header: "Invited",
		cell: ({ row }) => (
			<span className="text-sm text-muted-foreground">
				{dateFmt.format(new Date(row.original.created_at))}
			</span>
		),
	},
	{
		id: "actions",
		header: "",
		cell: ({ row }) => (
			<RevokeInviteButton
				vaultId={row.original.vault_id}
				collaboratorId={row.original.id}
				status={row.original.status}
			/>
		),
	},
];
