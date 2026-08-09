import { type ApiClient, api } from "#/services/api";
import type {
	VaultCollaborator,
	VaultDetail,
	VaultSummary,
} from "./vault.types.ts";

class VaultService {
	constructor(private readonly client: ApiClient = api) {}

	private base(workspaceId: string) {
		return `/workspaces/${encodeURIComponent(workspaceId)}/vaults`;
	}

	list(workspaceId: string) {
		return this.client.get<VaultSummary[]>(`${this.base(workspaceId)}`);
	}

	get(workspaceId: string, vaultId: string) {
		return this.client.get<VaultDetail>(
			`${this.base(workspaceId)}/${encodeURIComponent(vaultId)}`,
		);
	}

	listCollaborators(workspaceId: string, vaultId: string) {
		return this.client.get<VaultCollaborator[]>(
			`${this.base(workspaceId)}/${encodeURIComponent(vaultId)}/collaborators`,
		);
	}

	revokeCollaborator(
		workspaceId: string,
		vaultId: string,
		collaboratorId: string,
	) {
		return this.client.delete(
			`${this.base(workspaceId)}/${encodeURIComponent(vaultId)}/collaborators/${encodeURIComponent(collaboratorId)}`,
		);
	}
}

export const vaultService = new VaultService();
