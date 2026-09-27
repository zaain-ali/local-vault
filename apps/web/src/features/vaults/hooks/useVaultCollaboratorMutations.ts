import { useMutation, useQueryClient } from "@tanstack/react-query";
import toast from "react-hot-toast";

import { VAULT_KEYS, vaultService } from "#/features/vaults/api";
import type { AddVaultMemberInput } from "#/features/vaults/api/vault.types.ts";
import { useWorkspaceStore } from "#/stores";

export function useAddVaultMember(vaultId: string) {
	const workspaceId = useWorkspaceStore((s) => s.active?.id);
	const qc = useQueryClient();

	return useMutation({
		mutationFn: (input: AddVaultMemberInput) => {
			if (!workspaceId) throw new Error("No workspace");
			return vaultService.addMember(workspaceId, vaultId, input);
		},
		onSuccess: async () => {
			toast.success("Member added. Grant their key from the CLI after you verify the fingerprint.");
			if (workspaceId) {
				await qc.invalidateQueries({
					queryKey: VAULT_KEYS.workspace(workspaceId),
				});
			}
		},
		onError: (error) => toast.error(error.message || "Could not add member"),
	});
}

export function useRemoveVaultMember(vaultId: string) {
	const workspaceId = useWorkspaceStore((s) => s.active?.id);
	const qc = useQueryClient();

	return useMutation({
		mutationFn: (userId: string) => {
			if (!workspaceId) throw new Error("No workspace");
			return vaultService.removeMember(workspaceId, vaultId, userId);
		},
		onSuccess: async () => {
			toast.success("Member removed. Rekey the environments they could read.");
			if (workspaceId) {
				await qc.invalidateQueries({
					queryKey: VAULT_KEYS.workspace(workspaceId),
				});
			}
		},
		onError: (error) => toast.error(error.message || "Could not remove member"),
	});
}

export function useReviewChangeRequest(vaultId: string) {
	const workspaceId = useWorkspaceStore((s) => s.active?.id);
	const qc = useQueryClient();

	return useMutation({
		mutationFn: (args: {
			env: string;
			id: string;
			action: "approve" | "reject";
		}) => {
			if (!workspaceId) throw new Error("No workspace");
			return args.action === "approve"
				? vaultService.approveChangeRequest(workspaceId, vaultId, args.env, args.id)
				: vaultService.rejectChangeRequest(workspaceId, vaultId, args.env, args.id);
		},
		onSuccess: async (_, vars) => {
			toast.success(vars.action === "approve" ? "Change request approved" : "Change request rejected");
			if (workspaceId) {
				await qc.invalidateQueries({
					queryKey: VAULT_KEYS.workspace(workspaceId),
				});
			}
		},
		onError: (error) => toast.error(error.message || "Could not review change request"),
	});
}
