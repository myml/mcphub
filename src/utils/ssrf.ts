import { lookup as dnsLookup } from 'node:dns/promises';
import { isIP } from 'node:net';

export class UnsafeUrlError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'UnsafeUrlError';
  }
}

export type SsrfLookup = (host: string) => Promise<string[]>;

// Operator-managed hostname allowlist whose entries may resolve to otherwise
// blocked internal addresses (loopback / RFC1918 / link-local). It exists so a
// deployment whose upstream MCP servers legitimately live on an intranet behind
// a private DNS zone can name those hosts explicitly, instead of granting every
// non-admin user blanket internal-network egress. Comma-separated; `*` is a
// wildcard matching any characters, so `*.corp.example` allows sub-domains
// (`a.corp.example`, `a.b.corp.example`) but not the apex, and
// `mirrord-*.corp.example` allows one family of hosts. Entries are matched on
// host name only — scheme, port and path are ignored.
export const ALLOWED_INTERNAL_HOSTS_ENV_VAR = 'MCPHUB_ALLOWED_INTERNAL_HOSTS';

// Normalize an allowlist entry or a URL hostname into a comparable host:
// lower-case, without scheme, credentials, path, port, brackets or trailing dot.
// `*` characters are preserved so patterns survive normalization intact.
const normalizeHost = (entry: string): string => {
  let value = entry.trim().toLowerCase();
  if (!value) {
    return '';
  }

  const schemeIndex = value.indexOf('://');
  if (schemeIndex !== -1) {
    value = value.slice(schemeIndex + 3);
  }

  const credentialsIndex = value.indexOf('@');
  if (credentialsIndex !== -1) {
    value = value.slice(credentialsIndex + 1);
  }

  value = value.split(/[/?#]/)[0];

  if (value.startsWith('[')) {
    const closingBracket = value.indexOf(']');
    value = closingBracket === -1 ? value.slice(1) : value.slice(1, closingBracket);
  } else if (value.indexOf(':') === value.lastIndexOf(':')) {
    // Exactly one colon means host:port; a bare IPv6 literal has several and is
    // left intact.
    const portIndex = value.indexOf(':');
    if (portIndex !== -1) {
      value = value.slice(0, portIndex);
    }
  }

  return value.replace(/\.+$/, '');
};

// Compiled allowlist patterns, keyed by normalized pattern. Bounded so an
// arbitrary explicit allowlist cannot grow the cache without limit.
const hostPatternCache = new Map<string, RegExp>();
const HOST_PATTERN_CACHE_LIMIT = 200;

const hostPatternToRegExp = (pattern: string): RegExp => {
  const cached = hostPatternCache.get(pattern);
  if (cached) {
    return cached;
  }

  // `*` matches any characters (dots included); every other character is
  // literal, so a pattern can never match a host it does not textually cover.
  const source = pattern.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*');
  const compiled = new RegExp(`^${source}$`);

  if (hostPatternCache.size >= HOST_PATTERN_CACHE_LIMIT) {
    hostPatternCache.clear();
  }
  hostPatternCache.set(pattern, compiled);
  return compiled;
};

export const parseAllowedInternalHosts = (raw: string | undefined): string[] => {
  if (!raw) {
    return [];
  }

  const hosts = raw
    .split(',')
    .map((entry) => normalizeHost(entry))
    // An entry made only of wildcards (`*`, `**`, `*.*`) would allowlist every
    // host and silently disable the guard, so it is dropped rather than honored.
    .filter((entry) => entry.length > 0 && !/^[*.\s]+$/.test(entry));

  return [...new Set(hosts)];
};

export const getAllowedInternalHosts = (
  env: NodeJS.ProcessEnv = process.env,
): string[] => parseAllowedInternalHosts(env[ALLOWED_INTERNAL_HOSTS_ENV_VAR]);

export const isAllowedInternalHost = (host: string, allowlist: readonly string[]): boolean => {
  if (allowlist.length === 0) {
    return false;
  }

  const normalized = normalizeHost(host);
  if (!normalized) {
    return false;
  }

  return allowlist.some((pattern) => hostPatternToRegExp(pattern).test(normalized));
};

export interface AssertSafeUrlOptions {
  // When true, skip the internal-IP blocklist (loopback / RFC1918 / link-local).
  // Use only for trusted callers (e.g. admin-owned servers) that legitimately
  // need to reach internal services.
  allowInternal?: boolean;
  // Hostnames that may resolve to blocked internal addresses even when
  // allowInternal is false. Defaults to the MCPHUB_ALLOWED_INTERNAL_HOSTS
  // environment allowlist; pass an explicit list (e.g. []) to bypass it.
  allowedInternalHosts?: readonly string[];
  lookup?: SsrfLookup;
}

// IPv4 blocked ranges as [start, end] inclusive 32-bit integers.
const IPV4_BLOCKED_RANGES: Array<[number, number]> = [
  [0x00000000, 0x00ffffff], // 0.0.0.0/8 unspecified
  [0x0a000000, 0x0affffff], // 10.0.0.0/8 RFC1918
  [0x64000000, 0x657fffff], // 100.64.0.0/10 CGNAT
  [0x7f000000, 0x7fffffff], // 127.0.0.0/8 loopback
  [0xa9fe0000, 0xa9feffff], // 169.254.0.0/16 link-local (IMDS)
  [0xac100000, 0xac1fffff], // 172.16.0.0/12 RFC1918
  [0xc0000000, 0xc00000ff], // 192.0.0.0/24 IETF protocol assignments
  [0xc0a80000, 0xc0a8ffff], // 192.168.0.0/16 RFC1918
  [0xc6120000, 0xc613ffff], // 198.18.0.0/15 benchmarking
];

function ipv4ToInt(ip: string): number {
  const [a, b, c, d] = ip.split('.').map(Number);
  return (((a * 256 + b) * 256 + c) * 256 + d) >>> 0;
}

function isBlockedIpv4Number(n: number): boolean {
  for (const [start, end] of IPV4_BLOCKED_RANGES) {
    if (n >= start && n <= end) return true;
  }
  return false;
}

// Expand an IPv6 textual form (including an embedded IPv4 tail) into 8 hex groups.
function expandIpv6(addr: string): string[] {
  if (addr.includes('.')) {
    const lastColon = addr.lastIndexOf(':');
    const v4 = addr.slice(lastColon + 1);
    const [a, b, c, d] = v4.split('.').map(Number);
    const hi = ((a << 8) | b) >>> 0;
    const lo = ((c << 8) | d) >>> 0;
    addr = `${addr.slice(0, lastColon + 1)}${hi.toString(16)}:${lo.toString(16)}`;
  }

  if (addr.includes('::')) {
    const [head, tail] = addr.split('::');
    const headParts = head ? head.split(':') : [];
    const tailParts = tail ? tail.split(':') : [];
    const missing = 8 - headParts.length - tailParts.length;
    return [...headParts, ...Array(Math.max(0, missing)).fill('0'), ...tailParts];
  }
  return addr.split(':');
}

function ipv6ToBigInt(addr: string): bigint {
  const groups = expandIpv6(addr);
  let result = 0n;
  for (const g of groups) {
    result = (result << 16n) | BigInt(parseInt(g || '0', 16));
  }
  return result;
}

function isBlockedIpv6(big: bigint): boolean {
  if (big === 0n || big === 1n) return true; // ::, ::1
  const top10 = big >> 118n;
  if (top10 === 0x3fan) return true; // fe80::/10 link-local
  if (top10 === 0x3fbn) return true; // fec0::/10 site-local (deprecated)
  if (big >> 120n === 0xffn) return true; // ff00::/8 multicast — never a valid dial target
  const top16 = big >> 112n;
  if (top16 === 0x2002n) return true; // 2002::/16 6to4 transition (deprecated, RFC 7526)
  if (top16 === 0x64ffn && big >> 80n === 0x64ff9b1n) return true; // 64:ff9b:1::/48 local-use NAT64
  const top32 = big >> 96n;
  if (top32 === 0x20010000n) return true; // 2001:0::/32 Teredo transition
  if (top32 === 0x64ff9bn) return true; // 64:ff9b::/96 NAT64 well-known prefix
  if (big >> 121n === 0x7en) return true; // fc00::/7 unique-local
  if (big >> 32n === 0xffffn) return isBlockedIpv4Number(Number(big & 0xffffffffn)); // ::ffff:a.b.c.d
  if (big < 0x100000000n) return isBlockedIpv4Number(Number(big)); // ::a.b.c.d (deprecated, compatible)
  return false;
}

export function isBlockedIp(ip: string): boolean {
  const family = isIP(ip);
  if (family === 4) return isBlockedIpv4Number(ipv4ToInt(ip));
  if (family === 6) return isBlockedIpv6(ipv6ToBigInt(ip));
  return true; // not an IP literal — fail closed
}

const defaultLookup: SsrfLookup = async (host) => {
  const records = await dnsLookup(host, { all: true });
  return records.map((r) => r.address);
};

export async function assertSafeUrl(
  rawUrl: string,
  opts: AssertSafeUrlOptions = {},
): Promise<string> {
  const {
    allowInternal = false,
    allowedInternalHosts = getAllowedInternalHosts(),
    lookup = defaultLookup,
  } = opts;

  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch {
    throw new UnsafeUrlError(`Invalid URL: ${rawUrl}`);
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new UnsafeUrlError(`Disallowed URL scheme: ${parsed.protocol}`);
  }

  if (allowInternal) {
    return parsed.href;
  }

  // Operator allowlist (MCPHUB_ALLOWED_INTERNAL_HOSTS): named intranet hosts may
  // resolve to blocked internal addresses. This lifts ONLY the internal-IP
  // blocklist — the scheme check above still applies, and a redirect to any host
  // outside the allowlist is still rejected hop by hop below.
  if (isAllowedInternalHost(parsed.hostname, allowedInternalHosts)) {
    return parsed.href;
  }

  const host = parsed.hostname;
  if (isIP(host) !== 0) {
    if (isBlockedIp(host)) {
      throw new UnsafeUrlError(`Blocked target IP: ${host}`);
    }
    return parsed.href;
  }

  let addresses: string[];
  try {
    addresses = await lookup(host);
  } catch {
    throw new UnsafeUrlError(`Unable to resolve host: ${host}`);
  }
  if (addresses.length === 0) {
    throw new UnsafeUrlError(`No addresses resolved for host: ${host}`);
  }
  for (const addr of addresses) {
    if (isBlockedIp(addr)) {
      throw new UnsafeUrlError(`Host ${host} resolves to blocked address: ${addr}`);
    }
  }

  return parsed.href;
}

export type FetchLike = (url: string | URL, init?: RequestInit) => Promise<Response>;

// Wraps a fetch so HTTP redirects (3xx) are followed manually with each hop
// validated against the SSRF blocklist, instead of letting the underlying
// fetch auto-follow to an attacker-chosen internal address. Validates the
// resolved Location (absolute or relative) on every hop and caps the chain
// at maxHops to avoid redirect loops. Each hop also honors the
// MCPHUB_ALLOWED_INTERNAL_HOSTS allowlist, so a redirect is followed only when
// its target host is allowlisted (or the caller passed allowInternal).
export function createRedirectValidatingFetch(
  baseFetch: FetchLike,
  allowInternal: boolean,
  lookup: SsrfLookup = defaultLookup,
): FetchLike {
  const maxHops = 5;
  return async (url, init) => {
    let currentUrl = typeof url === 'string' ? url : url.toString();
    let hops = 0;
    currentUrl = await assertSafeUrl(currentUrl, { allowInternal, lookup });
    let response = await baseFetch(currentUrl, { ...init, redirect: 'manual' });
    while (
      response.status >= 300 &&
      response.status < 400 &&
      response.status !== 304 &&
      hops < maxHops
    ) {
      const location = response.headers.get('location');
      if (!location) {
        return response;
      }
      const resolvedUrl = new URL(location, currentUrl).toString();
      currentUrl = await assertSafeUrl(resolvedUrl, { allowInternal, lookup });
      hops++;
      response = await baseFetch(currentUrl, { ...init, redirect: 'manual' });
    }
    if (response.status >= 300 && response.status < 400 && response.status !== 304) {
      throw new UnsafeUrlError('Too many redirects');
    }
    return response;
  };
}
