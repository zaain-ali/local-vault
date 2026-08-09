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

export function vaultCollaboratorsQuery(workspaceId: string, vaultId: string) {
	return queryOptions({
		queryKey: VAULT_KEYS.collaborators(workspaceId, vaultId),
		queryFn: async () => {
			const res = await vaultService.listCollaborators(workspaceId, vaultId);
			return res.data;
		},
		staleTime: 15_000,
	});
}
