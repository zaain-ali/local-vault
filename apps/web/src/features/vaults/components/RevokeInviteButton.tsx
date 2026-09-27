import { Button } from "#/components/ui";
import { useRemoveVaultMember } from "#/features/vaults/hooks";

export function RevokeInviteButton({
	vaultId,
	userId,
}: {
	vaultId: string;
	userId: string;
	collaboratorId?: string;
	status?: string;
}) {
	const remove = useRemoveVaultMember(vaultId);

	return (
		<Button
			variant="ghost"
			size="sm"
			disabled={remove.isPending}
			onClick={() => remove.mutate(userId)}
		>
			Remove
		</Button>
	);
}
