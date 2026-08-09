import { parseAsStringLiteral } from "nuqs";

export const VAULT_TABS = ["devices", "invites"] as const;

export type VaultTab = (typeof VAULT_TABS)[number];

export const vaultDetailSearchParams = {
	tab: parseAsStringLiteral(VAULT_TABS).withDefault("devices"),
};

export const vaultDetailSearchOptions = {
	history: "replace" as const,
	shallow: true,
};
