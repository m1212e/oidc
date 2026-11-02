export function toList(
  value: string | readonly string[] | undefined,
): string[] {
  if (value === undefined) return [];
  return typeof value === "string" ? [value] : [...value];
}

/**
 * Checks {@link OidcCoreOptions.resource}: RFC 8707 wants each one an
 * absolute URI without a fragment, and a provider refusing one would only
 * say so at the first login.
 */
export function resolveResources(
  resource: string | readonly string[] | undefined,
): string[] {
  const resources = toList(resource);
  for (const value of resources) {
    let url: URL;
    try {
      url = new URL(value);
    } catch {
      throw new TypeError(
        `invalid resource ("${value}"): a resource indicator must be an absolute URI (RFC 8707)`,
      );
    }
    if (url.hash) {
      throw new TypeError(
        `invalid resource ("${value}"): a resource indicator must not carry a fragment (RFC 8707)`,
      );
    }
  }
  return resources;
}

/** `parameters` with one `resource` per configured resource indicator. */
export function withResources(
  parameters: Record<string, string>,
  resources: readonly string[],
): URLSearchParams {
  const params = new URLSearchParams(parameters);
  for (const resource of resources) params.append("resource", resource);
  return params;
}
