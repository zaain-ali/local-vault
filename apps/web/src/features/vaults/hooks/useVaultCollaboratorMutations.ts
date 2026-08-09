import { useMutation, useQueryClient } from "@tanstack/react-query";
import toast from "react-hot-toast";

import { VAULT_KEYS, vaultService } from "#/features/vaults/api";
import { useWorkspaceStore } from "#/stores";

export function useRevokeCollaborator(vaultId: string) {
	const workspaceId = useWorkspaceStore((s) => s.active?.id);
	const qc = useQueryClient();

	return useMutation({
		mutationFn: (collaboratorId: string) => {
			if (!workspaceId) throw new Error("No workspace");
			return vaultService.revokeCollaborator(
				workspaceId,
				vaultId,
				collaboratorId,
			);
		},
		onSuccess: async () => {
			toast.success("Invite revoked");
			if (workspaceId) {
				await qc.invalidateQueries({
					queryKey: VAULT_KEYS.collaborators(workspaceId, vaultId),
				});
			}
		},
		onError: (error) => toast.error(error.message || "Could not revoke invite"),
	});
}
