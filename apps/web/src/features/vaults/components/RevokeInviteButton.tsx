import { Button } from "#/components/ui";
import { useRevokeCollaborator } from "#/features/vaults/hooks";

export function RevokeInviteButton({
	vaultId,
	collaboratorId,
	status,
}: {
	vaultId: string;
	collaboratorId: string;
	status: string;
}) {
	const revoke = useRevokeCollaborator(vaultId);
	if (status === "active" || status === "revoked") return null;

	return (
		<Button
			variant="ghost"
			size="sm"
			disabled={revoke.isPending}
			onClick={() => revoke.mutate(collaboratorId)}
		>
			Revoke
		</Button>
	);
}
