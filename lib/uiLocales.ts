import { OidcInputError } from "./errors";

/** A language tag as used by `ui_locales`: BCP47-shaped, e.g. `de`, `de-DE`, `zh-Hans-CN`. */
const LANGUAGE_TAG = /^[A-Za-z0-9]+(?:-[A-Za-z0-9]+)*$/;

/**
 * Turns a preferred UI language list into the space-separated `ui_locales`
 * value (OIDC Core §3.1.2.1, also used by RP-Initiated Logout §2). Accepts one
 * tag, a space-separated string or an array, most preferred first. `undefined`
 * sends none.
 */
export function resolveUiLocales(
  uiLocales: string | readonly string[] | undefined,
): string | undefined {
  if (uiLocales === undefined) return undefined;
  const tags =
    typeof uiLocales === "string"
      ? uiLocales.split(/\s+/).filter(Boolean)
      : Array.isArray(uiLocales)
        ? [...uiLocales]
        : [];
  if (
    tags.length === 0 ||
    !tags.every((tag) => typeof tag === "string" && LANGUAGE_TAG.test(tag))
  ) {
    throw new OidcInputError(
      `invalid uiLocales (${JSON.stringify(uiLocales)}): expected language tags such as "de", "de-DE" or ["de", "en"]`,
    );
  }
  return tags.join(" ");
}
