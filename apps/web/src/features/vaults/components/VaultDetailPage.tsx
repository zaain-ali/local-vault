import { useQueryStates } from "nuqs";

import { TabGroup } from "#/components/shared";
import { Button, DataTable } from "#/components/ui";
import { canManageInvites } from "#/features/members/utils/canManageInvites.ts";
import type {
	ChangeRequest,
	PendingGrant,
	VaultEnvironment,
	VaultMember,
} from "#/features/vaults/api";
import {
	useChangeRequests,
	usePendingGrants,
	useRemoveVaultMember,
	useReviewChangeRequest,
	useVault,
} from "#/features/vaults/hooks";
import {
	type VaultTab,
	vaultDetailSearchOptions,
	vaultDetailSearchParams,
} from "#/features/vaults/utils";
import { useModalStore, useWorkspaceStore } from "#/stores";

import {
	changeRequestColumns,
	environmentColumns,
	grantColumns,
	memberColumns,
} from "./columns.tsx";

export function VaultDetailPage({ vaultId }: { vaultId: string }) {
	const role = useWorkspaceStore((s) => s.active?.role);
	const canManage = canManageInvites(role);
	const openModal = useModalStore((s) => s.openModal);
	const [{ tab }, setParams] = useQueryStates(
		vaultDetailSearchParams,
		vaultDetailSearchOptions,
	);

	const { data: vault, isLoading, isError, error } = useVault(vaultId);
	const members = vault?.members ?? [];
	const envs = vault?.environments ?? [];
	const envNames = envs.map((e) => e.name);

	const pending = usePendingGrants(vaultId, canManage);
	const requests = useChangeRequests(vaultId, envNames, canManage);
	const remove = useRemoveVaultMember(vaultId);
	const review = useReviewChangeRequest(vaultId);

	const activeTab: VaultTab = tab;

	return (
		<div className="flex flex-col gap-6 p-6">
			<div className="flex items-start justify-between gap-4">
				<div>
					<h1 className="text-xl font-semibold tracking-tight">
						{vault?.name ?? "Vault"}
					</h1>
					<p className="text-sm text-muted-foreground">
						Members decrypt only the environments they have a key grant for.
						Verify fingerprints before granting.
					</p>
				</div>
				{canManage ? (
					<Button
						onClick={() =>
							openModal({
								type: "invite-vault-member",
								props: { vaultId, envs: envNames },
							})
						}
					>
						Add member
					</Button>
				) : null}
			</div>

			<TabGroup
				value={activeTab}
				onValueChange={(value) => setParams({ tab: value as VaultTab })}
				items={[
					{
						value: "members",
						label: "Members",
						count: members.length,
						content: (
							<MembersTable
								members={members}
								isLoading={isLoading}
								isError={isError}
								errorMessage={error?.message}
								onRemove={canManage ? (id) => remove.mutate(id) : undefined}
							/>
						),
					},
					{
						value: "grants",
						label: "Pending grants",
						count: pending.data?.length ?? 0,
						content: (
							<GrantsTable
								grants={pending.data ?? []}
								isLoading={pending.isLoading}
								isError={pending.isError}
								errorMessage={pending.error?.message}
							/>
						),
					},
					{
						value: "environments",
						label: "Environments",
						count: envs.length,
						content: (
							<EnvironmentsPanel
								envs={envs}
								requests={requests.data ?? []}
								isLoading={isLoading || requests.isLoading}
								isError={isError || requests.isError}
								errorMessage={error?.message ?? requests.error?.message}
								onReview={
									canManage
										? (row, action) =>
												review.mutate({ env: row.env, id: row.id, action })
										: undefined
								}
							/>
						),
					},
				]}
			/>
		</div>
	);
}

function MembersTable({
	members,
	isLoading,
	isError,
	errorMessage,
	onRemove,
}: {
	members: VaultMember[];
	isLoading: boolean;
	isError: boolean;
	errorMessage?: string;
	onRemove?: (userId: string) => void;
}) {
	return (
		<DataTable
			columns={memberColumns(onRemove)}
			data={members}
			isLoading={isLoading}
			errorMessage={
				isError ? (errorMessage ?? "Could not load members.") : undefined
			}
			emptyMessage="No members yet."
		/>
	);
}

function GrantsTable({
	grants,
	isLoading,
	isError,
	errorMessage,
}: {
	grants: PendingGrant[];
	isLoading: boolean;
	isError: boolean;
	errorMessage?: string;
}) {
	return (
		<div className="flex flex-col gap-4">
			<p className="text-xs text-muted-foreground">
				Compare each fingerprint out of band, then grant from an unlocked CLI:{" "}
				<code className="font-mono">lv access grant</code>
			</p>
			<DataTable
				columns={grantColumns}
				data={grants}
				isLoading={isLoading}
				errorMessage={
					isError ? (errorMessage ?? "Could not load pending grants.") : undefined
				}
				emptyMessage="No pending grants."
			/>
		</div>
	);
}

function EnvironmentsPanel({
	envs,
	requests,
	isLoading,
	isError,
	errorMessage,
	onReview,
}: {
	envs: VaultEnvironment[];
	requests: ChangeRequest[];
	isLoading: boolean;
	isError: boolean;
	errorMessage?: string;
	onReview?: (row: ChangeRequest, action: "approve" | "reject") => void;
}) {
	return (
		<div className="flex flex-col gap-8">
			<DataTable
				columns={environmentColumns}
				data={envs}
				isLoading={isLoading}
				errorMessage={
					isError ? (errorMessage ?? "Could not load environments.") : undefined
				}
				emptyMessage="No environments."
			/>
			{requests.length > 0 || onReview ? (
				<div className="flex flex-col gap-3">
					<h2 className="text-sm font-medium">Pending change requests</h2>
					<DataTable
						columns={changeRequestColumns(onReview)}
						data={requests}
						emptyMessage="No pending change requests."
					/>
				</div>
			) : null}
		</div>
	);
}
