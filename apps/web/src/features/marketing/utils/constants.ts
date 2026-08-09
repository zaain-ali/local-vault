import {
	KeyRound,
	Laptop,
	ScrollText,
	Settings,
	ShieldCheck,
	Users,
	Vault,
	WifiOff,
} from "lucide-react";

import type {
	ConsoleNavItem,
	ConsoleStat,
	CryptoPrimitive,
	Feature,
	FooterColumn,
	InstallPlatform,
	MarketingLink,
	OnboardingStep,
	ProductTab,
	RelayLedgerEntry,
	TerminalLine,
	TrustPoint,
	VaultRow,
} from "#/features/marketing/types";

/** Section anchors — kept here so the nav, footer and sections can't drift apart. */
export const SECTION_IDS = {
	top: "top",
	product: "product",
	how: "how",
	features: "features",
	security: "security",
	install: "install",
} as const;

/** Off-site destinations. Everything else on this page is an in-page anchor. */
export const EXTERNAL_LINKS = {
	github: "https://github.com/zain-23/local-vault",
	releases: "https://github.com/zain-23/local-vault/releases",
	license: "https://github.com/zain-23/local-vault/blob/main/LICENSE",
} as const;

/**
 * `install.sh` auto-detects `darwin` vs `linux`, so the same one-liner covers
 * both. There's no real Windows installer, only release archives, so that tab
 * links straight to GitHub instead of showing a made-up package-manager command.
 */
const INSTALL_SH_COMMAND =
	"curl -fsSL https://raw.githubusercontent.com/zain-23/local-vault/main/install.sh | bash";

export const INSTALL_PLATFORMS: InstallPlatform[] = [
	{ id: "linux", label: "Linux", kind: "command", command: INSTALL_SH_COMMAND },
	{ id: "macos", label: "macOS", kind: "command", command: INSTALL_SH_COMMAND },
	{
		id: "windows",
		label: "Windows",
		kind: "download",
		href: EXTERNAL_LINKS.releases,
	},
];

export const NAV_LINKS: MarketingLink[] = [
	{ label: "Product", href: `#${SECTION_IDS.product}` },
	{ label: "How it works", href: `#${SECTION_IDS.how}` },
	{ label: "Features", href: `#${SECTION_IDS.features}` },
	{ label: "Security", href: `#${SECTION_IDS.security}` },
	{ label: "Docs", href: EXTERNAL_LINKS.github, external: true },
];

export const HERO_TRUST_POINTS: TrustPoint[] = [
	{ id: "no-cloud", label: "No cloud storage" },
	{ id: "offline", label: "Works offline" },
	{ id: "mit", label: "MIT licensed" },
	{ id: "platforms", label: "Linux, macOS & Windows" },
];

/* ── product tour ───────────────────────────────────────────────────── */

export const PRODUCT_TABS: ProductTab[] = [
	{
		id: "cli",
		label: "Command line",
		frameTitle: "zsh — localvault",
		frameBadge: "synced",
	},
	{
		id: "web",
		label: "Web console",
		frameTitle: "app.localvault.dev/vaults",
		frameBadge: "9 devices",
	},
];

/**
 * The showcase transcript: the product doing its one job — encrypt on-device,
 * pair peer-to-peer, inject at runtime. Add or reorder lines here.
 */
export const TERMINAL_TRANSCRIPT: TerminalLine[] = [
	{
		id: "init",
		segments: [{ text: "$", tone: "prompt" }, { text: "lv init" }],
	},
	{
		id: "init-pass",
		segments: [
			{ text: "passphrase:", tone: "muted" },
			{ text: "••••••••••••", tone: "muted" },
		],
	},
	{
		id: "init-out",
		segments: [
			{ text: "✓", tone: "success" },
			{ text: "vault created" },
			{ text: "— argon2id → aes-256-gcm", tone: "muted" },
		],
	},
	{
		id: "pair",
		segments: [{ text: "$", tone: "prompt" }, { text: "lv pair" }],
	},
	{
		id: "pair-code",
		segments: [
			{ text: "pairing code", tone: "muted" },
			{ text: "4F2-9QK", tone: "warning" },
			{ text: "— read this to your teammate", tone: "muted" },
		],
	},
	{
		id: "pair-out",
		segments: [
			{ text: "✓", tone: "success" },
			{ text: "dana's mac approved" },
			{ text: "— x25519 key exchange complete", tone: "muted" },
		],
	},
	{
		id: "push",
		segments: [{ text: "$", tone: "prompt" }, { text: "lv push" }],
	},
	{
		id: "push-out",
		segments: [
			{ text: "✓", tone: "success" },
			{ text: "14 secrets sealed, 4.2 KB relayed" },
			{ text: "— 0 bytes of plaintext on the wire", tone: "muted" },
		],
	},
	{
		id: "run",
		segments: [
			{ text: "$", tone: "prompt" },
			{ text: "lv run -- npm run dev" },
		],
	},
	{
		id: "run-out",
		segments: [
			{
				text: "injected 14 secrets into the process env — nothing written to disk",
				tone: "muted",
			},
		],
	},
	{ id: "idle", segments: [{ text: "$", tone: "prompt" }], caret: true },
];

export const CONSOLE_NAV_ITEMS: ConsoleNavItem[] = [
	{ id: "vaults", label: "Vaults", icon: Vault, active: true },
	{ id: "members", label: "Members", icon: Users },
	{ id: "devices", label: "Devices", icon: Laptop },
	{ id: "audit", label: "Audit log", icon: ScrollText },
	{ id: "settings", label: "Settings", icon: Settings },
];

export const CONSOLE_STATS: ConsoleStat[] = [
	{ id: "secrets", label: "Secrets", value: 128, countUp: true },
	{ id: "devices", label: "Paired devices", value: 9, countUp: true },
	{ id: "plaintext", label: "Plaintext stored", value: 0, tone: "success" },
];

export const CONSOLE_VAULTS: VaultRow[] = [
	{
		id: "api-production",
		name: "api-production",
		secrets: 42,
		members: 6,
		lastSync: "2m ago",
		status: "synced",
		statusLabel: "synced",
	},
	{
		id: "api-staging",
		name: "api-staging",
		secrets: 38,
		members: 6,
		lastSync: "11m ago",
		status: "synced",
		statusLabel: "synced",
	},
	{
		id: "web-frontend",
		name: "web-frontend",
		secrets: 24,
		members: 4,
		lastSync: "1h ago",
		status: "synced",
		statusLabel: "synced",
	},
	{
		id: "data-pipeline",
		name: "data-pipeline",
		secrets: 19,
		members: 3,
		lastSync: "—",
		status: "pending",
		statusLabel: "pending peer",
	},
	{
		id: "infra-terraform",
		name: "infra-terraform",
		secrets: 5,
		members: 2,
		lastSync: "3h ago",
		status: "synced",
		statusLabel: "synced",
	},
];

/* ── how it works ───────────────────────────────────────────────────── */

export const ONBOARDING_STEPS: OnboardingStep[] = [
	{
		id: "create",
		title: "Create the vault",
		description:
			"Your passphrase is stretched with Argon2id and the vault is sealed with AES-256-GCM. The passphrase itself is never stored or sent anywhere.",
		command: "lv init",
	},
	{
		id: "pair",
		title: "Pair a teammate",
		description:
			"A six-digit code appears. Read it out on the call, approve once, and the two machines agree on a key over X25519 — directly with each other.",
		command: "lv pair",
	},
	{
		id: "run",
		title: "Run your app",
		description:
			"Secrets are injected straight into the process environment. Nothing is written to a file that could get committed by accident.",
		command: "lv run -- npm run dev",
	},
];

/* ── features ───────────────────────────────────────────────────────── */

/** The wide bento tile — rendered with the relay diagram + ledger visual. */
export const RELAY_FEATURE: Feature = {
	id: "p2p",
	icon: ShieldCheck,
	title: "Peer-to-peer by default",
	description:
		"Two laptops behind two home routers can't always reach each other, so LocalVault runs a relay to introduce them. It forwards one sealed blob and forgets it — here's everything it holds while doing that.",
};

export const RELAY_LEDGER: RelayLedgerEntry[] = [
	{ id: "blob_size", key: "blob_size", value: "4.2 KB", exposed: true },
	{ id: "routed_at", key: "routed_at", value: "14:22:07Z", exposed: true },
	{
		id: "secret_names",
		key: "secret_names",
		value: "never sent",
		exposed: false,
	},
	{
		id: "secret_values",
		key: "secret_values",
		value: "never sent",
		exposed: false,
	},
	{
		id: "vault_key",
		key: "vault_key",
		value: "never leaves device",
		exposed: false,
	},
	{
		id: "passphrase",
		key: "passphrase",
		value: "never exists off-device",
		exposed: false,
	},
];

export const FEATURES: Feature[] = [
	{
		id: "device-approval",
		icon: Laptop,
		title: "Device approval",
		description:
			"A new machine shows a six-digit code. Approve it once and it's trusted by Ed25519 identity from then on — no shared password to rotate.",
		command: "$ lv pair",
		commandAccent: "lv pair",
	},
	{
		id: "workspaces",
		icon: Users,
		title: "Workspaces & members",
		description:
			"Share a vault scoped to a team, not to whoever still happens to be in the group chat. Revoke a member and their devices lose access.",
		command: "$ lv members add dana",
		commandAccent: "lv members add",
	},
	{
		id: "audit",
		icon: ScrollText,
		title: "Full audit trail",
		description:
			'Every read, write, and sync is logged. "Who rotated the staging key on Tuesday" becomes a query with an answer instead of a thread with guesses.',
		command: "$ lv audit --since 7d",
		commandAccent: "lv audit",
	},
	{
		id: "offline",
		icon: WifiOff,
		title: "Offline first",
		description:
			"The vault is a local file, so it works on a plane. It syncs the moment a paired machine is reachable again.",
		command: "$ lv run -- pytest",
		commandAccent: "lv run",
	},
	{
		id: "console",
		icon: KeyRound,
		title: "Web console with 2FA",
		description:
			"Manage devices, members, and audit history in a browser when you'd rather click than type. Protected by TOTP and magic links.",
		command: "app.localvault.dev",
	},
];

/* ── security ───────────────────────────────────────────────────────── */

export const CRYPTO_PRIMITIVES: CryptoPrimitive[] = [
	{
		id: "argon2id",
		name: "Argon2id",
		role: "Key derivation",
		description:
			"Stretches your passphrase into a vault key on your device. Never stored, never transmitted.",
	},
	{
		id: "aes",
		name: "AES-256-GCM",
		role: "Vault encryption",
		description:
			"Authenticated encryption, so tampering fails loudly instead of quietly.",
	},
	{
		id: "x25519",
		name: "X25519",
		role: "Key exchange",
		description:
			"Two devices agree on a shared key directly. No password to share, no third party to trust.",
	},
	{
		id: "ed25519",
		name: "Ed25519",
		role: "Device identity",
		description:
			"Each device carries a signed identity, so vaults only open for machines you approved.",
	},
];

/* ── footer ─────────────────────────────────────────────────────────── */

export const FOOTER_BLURB =
	"An encrypted secrets vault that syncs peer-to-peer between your team's machines. No cloud. No leaks.";

export const FOOTER_COLUMNS: FooterColumn[] = [
	{
		id: "product",
		title: "Product",
		links: [
			{ label: "How it works", href: `#${SECTION_IDS.how}` },
			{ label: "Features", href: `#${SECTION_IDS.features}` },
			{ label: "Security", href: `#${SECTION_IDS.security}` },
			{ label: "Download", href: `#${SECTION_IDS.install}` },
		],
	},
	{
		id: "company",
		title: "Company",
		links: [
			{ label: "GitHub", href: EXTERNAL_LINKS.github, external: true },
			{ label: "License", href: EXTERNAL_LINKS.license, external: true },
		],
	},
];
