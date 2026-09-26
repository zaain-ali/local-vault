package email

// EmailKind names which email to send - the worker switches on this value
type EmailKind string

const (
	KindWorkspaceInvite         EmailKind = "workspace_invite"
	KindVaultCollaboratorInvite EmailKind = "vault_collaborator_invite"
)

// EmailJob is the message we put on the queue - json-encoded in the body
type EmailJob struct {
	Kind EmailKind `json:"kind"`
	To   string    `json:"to"`
	Name string    `json:"name"`
	URL  string    `json:"url"`

	// vault_collaborator_invite: Name = vault name
	Inviter string `json:"inviter,omitempty"` // who granted access (display name or email)
	Envs    string `json:"envs,omitempty"`    // comma-separated environment names
}
