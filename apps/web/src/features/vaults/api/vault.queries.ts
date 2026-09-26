import { queryOptions } from "@tanstack/react-query";

import { VAULT_KEYS, vaultService } from "#/features/vaults/api";

export function vaultsQuery(workspaceId: string) {
	return queryOptions({
		queryKey: VAULT_KEYS.list(workspaceId),
		queryFn: async () => {
			const res = await vaultService.list(workspaceId);
			return res.data;
		},
		staleTime: 30_000,
	});
}

export function vaultQuery(workspaceId: string, vaultId: string) {
	return queryOptions({
		queryKey: VAULT_KEYS.detail(workspaceId, vaultId),
		queryFn: async () => {
			const res = await vaultService.get(workspaceId, vaultId);
			return res.data;
		},
		staleTime: 15_000,
	});
}

export function pendingGrantsQuery(workspaceId: string, vaultId: string) {
	return queryOptions({
		queryKey: VAULT_KEYS.pendingGrants(workspaceId, vaultId),
		queryFn: async () => {
			const res = await vaultService.pendingGrants(workspaceId, vaultId);
			return res.data;
		},
		staleTime: 10_000,
	});
}

export function changeRequestsQuery(
	workspaceId: string,
	vaultId: string,
	envs: string[],
) {
	return queryOptions({
		queryKey: VAULT_KEYS.changeRequests(workspaceId, vaultId),
		queryFn: async () => {
			const lists = await Promise.all(
				envs.map((env) => vaultService.changeRequests(workspaceId, vaultId, env)),
			);
			return lists.flatMap((r) => r.data ?? []);
		},
		staleTime: 10_000,
	});
}
