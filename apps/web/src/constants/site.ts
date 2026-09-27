/** Canonical public origin for absolute meta URLs (og:image, etc.). */
export const SITE_URL = (import.meta.env.VITE_SITE_URL ?? "https://localvault.dev").replace(/\/+$/, "");

export const SITE_NAME = "LocalVault";

/** GitHub owner/repo — star count API, marketing links, etc. */
export const GITHUB_REPO = "zaain-ali/local-vault";

export const OG_IMAGE_PATH = "/og.jpg";
export const OG_IMAGE_URL = `${SITE_URL}${OG_IMAGE_PATH}`;
export const OG_IMAGE_WIDTH = 1200;
export const OG_IMAGE_HEIGHT = 630;

export const DEFAULT_TITLE = "LocalVault — Stop sharing secrets over Slack";
export const DEFAULT_DESCRIPTION =
	"LocalVault replaces .env files with an encrypted vault that syncs peer-to-peer between your team's machines. No cloud storage, works offline, MIT licensed.";
