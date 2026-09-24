import { create } from "zustand";

// The set of modals the GlobalModalProvider knows how to render. Add a key here
// (and a matching entry in the provider's registry) to introduce a new modal.
export type ModalType =
	| "invite-member"
	| "invite-vault-member"
	| "change-role"
	| "remove-member"
	| "cancel-invite"
	| "create-workspace";

type ModalArgs = {
	type: ModalType;
	props?: Record<string, unknown>;
};

// Per-modal payload. Kept loose (unknown) so the store stays decoupled from
// feature types; each modal casts its own props at the point of use.
interface ModalState {
	type: ModalType | null;
	props: Record<string, unknown>;
	openModal: (args: ModalArgs) => void;
	closeModal: () => void;
}

export const useModalStore = create<ModalState>((set) => ({
	type: null,
	props: {},
	openModal: ({ type, props = {} }) => set({ type, props }),
	closeModal: () => set({ type: null, props: {} }),
}));
