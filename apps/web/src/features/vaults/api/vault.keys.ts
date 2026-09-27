export const VAULT_KEYS = {
	all: ["vaults"] as const,
	workspace: (workspaceId: string) => [...VAULT_KEYS.all, workspaceId] as const,
	list: (workspaceId: string) =>
		[...VAULT_KEYS.workspace(workspaceId), "list"] as const,
	detail: (workspaceId: string, vaultId: string) =>
		[...VAULT_KEYS.workspace(workspaceId), "detail", vaultId] as const,
	pendingGrants: (workspaceId: string, vaultId: string) =>
		[...VAULT_KEYS.workspace(workspaceId), "pending-grants", vaultId] as const,
	changeRequests: (workspaceId: string, vaultId: string) =>
		[...VAULT_KEYS.workspace(workspaceId), "change-requests", vaultId] as const,
};
