import { parseAsStringLiteral } from "nuqs";

export const VAULT_TABS = ["members", "grants", "environments"] as const;

export type VaultTab = (typeof VAULT_TABS)[number];

export const vaultDetailSearchParams = {
	tab: parseAsStringLiteral(VAULT_TABS).withDefault("members"),
};

export const vaultDetailSearchOptions = {
	history: "replace" as const,
	shallow: true,
};
