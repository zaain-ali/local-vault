import { type ApiClient, api } from "#/services/api";
import type {
	AddVaultMemberInput,
	ChangeRequest,
	PendingGrant,
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

	addMember(workspaceId: string, vaultId: string, input: AddVaultMemberInput) {
		return this.client.post(
			`${this.base(workspaceId)}/${encodeURIComponent(vaultId)}/members`,
			input,
		);
	}

	removeMember(workspaceId: string, vaultId: string, userId: string) {
		return this.client.delete(
			`${this.base(workspaceId)}/${encodeURIComponent(vaultId)}/members/${encodeURIComponent(userId)}`,
		);
	}

	pendingGrants(workspaceId: string, vaultId: string) {
		return this.client.get<PendingGrant[]>(
			`${this.base(workspaceId)}/${encodeURIComponent(vaultId)}/grants/pending`,
		);
	}

	changeRequests(workspaceId: string, vaultId: string, env: string) {
		return this.client.get<ChangeRequest[]>(
			`${this.base(workspaceId)}/${encodeURIComponent(vaultId)}/environments/${encodeURIComponent(env)}/change-requests`,
			{ params: { status: "pending" } },
		);
	}

	approveChangeRequest(
		workspaceId: string,
		vaultId: string,
		env: string,
		id: string,
	) {
		return this.client.post(
			`${this.base(workspaceId)}/${encodeURIComponent(vaultId)}/environments/${encodeURIComponent(env)}/change-requests/${encodeURIComponent(id)}/approve`,
			{},
		);
	}

	rejectChangeRequest(
		workspaceId: string,
		vaultId: string,
		env: string,
		id: string,
	) {
		return this.client.post(
			`${this.base(workspaceId)}/${encodeURIComponent(vaultId)}/environments/${encodeURIComponent(env)}/change-requests/${encodeURIComponent(id)}/reject`,
			{},
		);
	}
}

export const vaultService = new VaultService();
