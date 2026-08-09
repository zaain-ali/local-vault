export type VaultSummary = {
	id: string;
	name: string;
	owner_device_id: string;
	peer_count: number;
	has_snapshot: boolean;
	created_at: string;
	updated_at: string;
};

export type VaultPeer = {
	device_id: string;
	device_name: string;
	user_id?: string;
	name?: string;
	email?: string;
	joined_at: string;
};

export type VaultDetail = {
	id: string;
	name: string;
	workspace_id: string;
	created_by: string;
	owner_device_id: string;
	peers: VaultPeer[];
	created_at: string;
	updated_at: string;
};

export type VaultCollaborator = {
	id: string;
	vault_id: string;
	user_id: string;
	email: string;
	invited_by: string;
	status: string;
	device_id?: string;
	device_name?: string;
	created_at: string;
	expires_at: string;
};
