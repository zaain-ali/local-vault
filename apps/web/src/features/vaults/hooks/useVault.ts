import { useQuery } from "@tanstack/react-query";

import {
	changeRequestsQuery,
	pendingGrantsQuery,
	vaultQuery,
} from "#/features/vaults/api";
import { useWorkspaceStore } from "#/stores";

export function useVault(vaultId: string) {
	const workspaceId = useWorkspaceStore((s) => s.active?.id);
	return useQuery({
		...vaultQuery(workspaceId ?? "", vaultId),
		enabled: Boolean(workspaceId && vaultId),
	});
}

export function usePendingGrants(vaultId: string, enabled: boolean) {
	const workspaceId = useWorkspaceStore((s) => s.active?.id);
	return useQuery({
		...pendingGrantsQuery(workspaceId ?? "", vaultId),
		enabled: Boolean(workspaceId && vaultId && enabled),
	});
}

export function useChangeRequests(
	vaultId: string,
	envs: string[],
	enabled: boolean,
) {
	const workspaceId = useWorkspaceStore((s) => s.active?.id);
	return useQuery({
		...changeRequestsQuery(workspaceId ?? "", vaultId, envs),
		enabled: Boolean(workspaceId && vaultId && enabled && envs.length > 0),
	});
}
