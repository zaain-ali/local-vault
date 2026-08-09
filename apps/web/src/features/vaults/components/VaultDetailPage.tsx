import { useQueryStates } from "nuqs";
import { useEffect } from "react";

import { TabGroup } from "#/components/shared";
import { DataTable } from "#/components/ui";
import { canManageInvites } from "#/features/members/utils/canManageInvites.ts";
import type { VaultCollaborator, VaultPeer } from "#/features/vaults/api";
import { useVault, useVaultCollaborators } from "#/features/vaults/hooks";
import {
	type VaultTab,
	vaultDetailSearchOptions,
	vaultDetailSearchParams,
} from "#/features/vaults/utils";
import { useWorkspaceStore } from "#/stores";

import { inviteColumns, peerColumns } from "./columns.tsx";

export function VaultDetailPage({ vaultId }: { vaultId: string }) {
	const role = useWorkspaceStore((s) => s.active?.role);
	const canManage = canManageInvites(role);
	const [{ tab }, setParams] = useQueryStates(
		vaultDetailSearchParams,
		vaultDetailSearchOptions,
	);

	const { data: vault, isLoading, isError, error } = useVault(vaultId);
	const {
		data: collaborators,
		isLoading: collabLoading,
		isError: collabError,
		error: collabErr,
	} = useVaultCollaborators(vaultId, canManage);

	useEffect(() => {
		if (!canManage && tab === "invites") {
			void setParams({ tab: "devices" });
		}
	}, [canManage, tab, setParams]);

	const activeTab: VaultTab = canManage ? tab : "devices";
	const peers = vault?.peers ?? [];
	const pendingInvites = (collaborators ?? []).filter(
		(c) => c.status === "pending",
	);

	return (
		<div className="flex flex-col gap-6 p-6">
			{canManage ? (
				<TabGroup
					value={activeTab}
					onValueChange={(value) => setParams({ tab: value as VaultTab })}
					items={[
						{
							value: "devices",
							label: "Devices",
							count: peers.length,
							content: (
								<DevicesTable
									peers={peers}
									isLoading={isLoading}
									isError={isError}
									errorMessage={error?.message}
								/>
							),
						},
						{
							value: "invites",
							label: "Pending invites",
							count: pendingInvites.length,
							content: (
								<InvitesTable
									invites={pendingInvites}
									isLoading={collabLoading}
									isError={collabError}
									errorMessage={collabErr?.message}
								/>
							),
						},
					]}
				/>
			) : (
				<DevicesTable
					peers={peers}
					isLoading={isLoading}
					isError={isError}
					errorMessage={error?.message}
				/>
			)}
		</div>
	);
}

function DevicesTable({
	peers,
	isLoading,
	isError,
	errorMessage,
}: {
	peers: VaultPeer[];
	isLoading: boolean;
	isError: boolean;
	errorMessage?: string;
}) {
	return (
		<DataTable
			columns={peerColumns}
			data={peers}
			isLoading={isLoading}
			errorMessage={
				isError ? (errorMessage ?? "Could not load devices.") : undefined
			}
			emptyMessage="No devices yet."
		/>
	);
}

function InvitesTable({
	invites,
	isLoading,
	isError,
	errorMessage,
}: {
	invites: VaultCollaborator[];
	isLoading: boolean;
	isError: boolean;
	errorMessage?: string;
}) {
	return (
		<div className="flex flex-col gap-4">
			<p className="text-xs text-muted-foreground">
				Invite from CLI:{" "}
				<code className="font-mono">lv invite email@company.com</code>. They
				join with the emailed code:{" "}
				<code className="font-mono">lv join ABCD-1234</code>.
			</p>
			<DataTable
				columns={inviteColumns}
				data={invites}
				isLoading={isLoading}
				errorMessage={
					isError ? (errorMessage ?? "Could not load invites.") : undefined
				}
				emptyMessage="No pending invites."
			/>
		</div>
	);
}
