export type EnvAccess = {
	env: string;
	permission: "read" | "write";
};

export type VaultEnvironment = {
	name: string;
	key_version: number;
	head_revision: number;
	protected: boolean;
	rekey_required: boolean;
	updated_at: string;
};

export type VaultMember = {
	user_id: string;
	name: string;
	email: string;
	role: "admin" | "member";
	env_access: EnvAccess[];
	fingerprint?: string;
	has_keys: boolean;
};

export type VaultSummary = {
	id: string;
	name: string;
	environments: VaultEnvironment[];
	member_count: number;
	my_role?: string;
	my_env_access?: EnvAccess[];
	created_at: string;
	updated_at: string;
};

export type VaultDetail = {
	id: string;
	workspace_id: string;
	name: string;
	created_by: string;
	environments: VaultEnvironment[];
	members: VaultMember[];
	my_role?: string;
	my_env_access?: EnvAccess[];
	created_at: string;
	updated_at: string;
};

export type PendingGrant = {
	env: string;
	key_version: number;
	recipient_type: "user" | "machine";
	recipient_id: string;
	label: string;
	email?: string;
	key_type: string;
	fingerprint: string;
};

export type ChangeRequest = {
	id: string;
	vault_id: string;
	env: string;
	base_revision: number;
	key_version: number;
	author_user_id: string;
	note: string;
	status: "pending" | "approved" | "rejected" | "stale";
	created_at: string;
};

export type AddVaultMemberInput = {
	email: string;
	role: "admin" | "member";
	env_access: EnvAccess[];
};

/** @deprecated kept so existing invite-column imports compile during the cutover */
export type VaultCollaborator = VaultMember & {
	id: string;
	vault_id: string;
	status: string;
};

export type VaultPeer = {
	device_id: string;
	device_name: string;
	user_id?: string;
	name?: string;
	email?: string;
	joined_at: string;
};
