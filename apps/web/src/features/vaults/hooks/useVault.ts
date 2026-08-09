import { useQuery } from "@tanstack/react-query";

import { vaultCollaboratorsQuery, vaultQuery } from "#/features/vaults/api";
import { useWorkspaceStore } from "#/stores";

export function useVault(vaultId: string) {
	const workspaceId = useWorkspaceStore((s) => s.active?.id);
	return useQuery({
		...vaultQuery(workspaceId ?? "", vaultId),
		enabled: Boolean(workspaceId && vaultId),
	});
}

export function useVaultCollaborators(vaultId: string, enabled: boolean) {
	const workspaceId = useWorkspaceStore((s) => s.active?.id);
	return useQuery({
		...vaultCollaboratorsQuery(workspaceId ?? "", vaultId),
		enabled: Boolean(workspaceId && vaultId && enabled),
	});
}
