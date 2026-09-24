import type { ComponentType } from "react";
import { Dialog } from "#/components/ui";
import { CancelInviteModal } from "#/features/members/modals/CancelInviteModal.tsx";
import { ChangeRoleModal } from "#/features/members/modals/ChangeRoleModal.tsx";
import { InviteMemberModal } from "#/features/members/modals/InviteMemberModal.tsx";
import { InviteVaultMemberModal } from "#/features/vaults/modals/InviteVaultMemberModal.tsx";
import { RemoveMemberModal } from "#/features/members/modals/RemoveMemberModal.tsx";
import { CreateWorkspaceModal } from "#/features/onboarding/modals/CreateWorkspaceModal.tsx";
import { type ModalType, useModalStore } from "#/stores/useModalStore";

// Registry: maps a modal type to the component that renders its DialogContent.
// never imports Dialog; it just calls openModal({ type }).
const MODAL_REGISTRY: Record<ModalType, ComponentType> = {
	"invite-member": InviteMemberModal,
	"invite-vault-member": InviteVaultMemberModal,
	"change-role": ChangeRoleModal,
	"remove-member": RemoveMemberModal,
	"cancel-invite": CancelInviteModal,
	"create-workspace": CreateWorkspaceModal,
};

// Mounted once in the protected shell. Owns the Dialog root + open state; the
// active registry component supplies the content.
export function GlobalModalProvider() {
	const { type, closeModal } = useModalStore();
	const ActiveModal = type ? MODAL_REGISTRY[type] : null;

	return (
		<Dialog open={type !== null} onOpenChange={(open) => !open && closeModal()}>
			{ActiveModal ? <ActiveModal /> : null}
		</Dialog>
	);
}
