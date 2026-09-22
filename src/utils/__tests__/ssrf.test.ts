import { afterEach, describe, expect, it, jest } from '@jest/globals';

import {
  ALLOWED_INTERNAL_HOSTS_ENV_VAR,
  assertSafeUrl,
  createRedirectValidatingFetch,
  isAllowedInternalHost,
  isBlockedIp,
  parseAllowedInternalHosts,
  UnsafeUrlError,
} from '../ssrf.js';

describe('isBlockedIp', () => {
  it.each([
    ['127.0.0.1', 'loopback'],
    ['127.255.255.255', 'loopback /8 upper'],
    ['10.0.0.1', 'RFC1918 10/8'],
    ['172.16.0.1', 'RFC1918 172.16/12 lower'],
    ['172.31.255.255', 'RFC1918 172.16/12 upper'],
    ['192.168.1.1', 'RFC1918 192.168/16'],
    ['169.254.169.254', 'link-local (IMDS)'],
    ['169.254.0.1', 'link-local lower'],
    ['0.0.0.0', 'unspecified'],
    ['::1', 'IPv6 loopback'],
    ['fe80::1', 'IPv6 link-local'],
    ['fc00::1', 'IPv6 ULA'],
    ['fd00::1', 'IPv6 ULA'],
    ['::', 'IPv6 unspecified'],
    ['::ffff:127.0.0.1', 'IPv4-mapped loopback'],
    ['::ffff:169.254.169.254', 'IPv4-mapped link-local'],
    ['64:ff9b::169.254.169.254', 'NAT64 well-known prefix embedding link-local'],
    ['64:ff9b::7f00:1', 'NAT64 embedding loopback'],
    ['64:ff9b:1::a9fe:a9fe', 'NAT64 local-use /48 embedding link-local'],
    ['2002:c0a8:0101::', '6to4 embedding 192.168.1.1'],
    ['2002:a9fe:a9fe::', '6to4 embedding link-local'],
    ['2002:0808:0808::', '6to4 even with public embedded IPv4 (deprecated, RFC 7526)'],
    ['2001:0:1111:2222:3333:4444:4455:5566', 'Teredo prefix 2001:0::/32'],
    ['fec0::1', 'site-local (deprecated)'],
    ['fec0:1234::1', 'site-local upper range feff::/16 boundary'],
    ['febf:ffff::1', 'link-local /10 upper boundary (fe80::/10 ends at febf)'],
  ])('blocks %s (%s)', (ip) => {
    expect(isBlockedIp(ip)).toBe(true);
  });

  it.each([
    ['8.8.8.8', 'Google DNS'],
    ['1.1.1.1', 'Cloudflare DNS'],
    ['172.32.0.1', 'just outside 172.16/12'],
    ['11.0.0.1', 'just outside 10/8'],
    ['2606:4700:4700::1111', 'Cloudflare IPv6'],
    ['2001:4860:4860::8888', 'Google IPv6 DNS (global unicast, not Teredo)'],
    ['2620:fe::fe', 'Quad9 IPv6'],
  ])('allows %s (%s)', (ip) => {
    expect(isBlockedIp(ip)).toBe(false);
  });
});

const lookup = (map: Record<string, string[]>) => (host: string) =>
  Promise.resolve(map[host] ?? []);

describe('assertSafeUrl', () => {
  it('rejects non-http(s) schemes', async () => {
    await expect(assertSafeUrl('file:///etc/passwd')).rejects.toThrow(UnsafeUrlError);
    await expect(assertSafeUrl('gopher://127.0.0.1/x')).rejects.toThrow(UnsafeUrlError);
  });

  it('rejects an IP-literal loopback URL without DNS', async () => {
    await expect(assertSafeUrl('http://127.0.0.1:8181/secret')).rejects.toThrow(UnsafeUrlError);
  });

  it('rejects the cloud metadata endpoint', async () => {
    await expect(assertSafeUrl('http://169.254.169.254/latest/meta-data/')).rejects.toThrow(
      UnsafeUrlError,
    );
  });

  it('rejects a hostname that resolves to a privateIP', async () => {
    await expect(
      assertSafeUrl('http://internal.example/admin', {
        lookup: lookup({ 'internal.example': ['10.0.0.5'] }),
      }),
    ).rejects.toThrow(UnsafeUrlError);
  });

  it('rejects a hostname that resolves to link-local', async () => {
    await expect(
      assertSafeUrl('http://meta.example/', {
        lookup: lookup({ 'meta.example': ['169.254.169.254'] }),
      }),
    ).rejects.toThrow(UnsafeUrlError);
  });

  it('fails closed when DNS resolves nothing', async () => {
    await expect(assertSafeUrl('http://unresolvable.invalid/')).rejects.toThrow(UnsafeUrlError);
  });

  it('rejects IPv4-mapped-IPv6 loopback', async () => {
    await expect(
      assertSafeUrl('http://mapped.example/', {
        lookup: lookup({ 'mapped.example': ['::ffff:127.0.0.1'] }),
      }),
    ).rejects.toThrow(UnsafeUrlError);
  });

  it('rejects a hostname with even one blocked resolved address', async () => {
    await expect(
      assertSafeUrl('http://mixed.example/', {
        lookup: lookup({ 'mixed.example': ['8.8.8.8', '127.0.0.1'] }),
      }),
    ).rejects.toThrow(UnsafeUrlError);
  });

  it('allows a hostname that resolves only to public IPs', async () => {
    await expect(
      assertSafeUrl('https://public.example/api', {
        lookup: lookup({ 'public.example': ['93.184.216.34'] }),
      }),
    ).resolves.toBe('https://public.example/api');
  });
});

describe('assertSafeUrl with allowInternal', () => {
  it('allows loopback when allowInternal is true', async () => {
    await expect(
      assertSafeUrl('http://127.0.0.1:8181/secret', { allowInternal: true }),
    ).resolves.toBe('http://127.0.0.1:8181/secret');
  });

  it('allows the metadata endpoint when allowInternal is true', async () => {
    await expect(
      assertSafeUrl('http://169.254.169.254/latest/meta-data/', {
        allowInternal: true,
      }),
    ).resolves.toBe('http://169.254.169.254/latest/meta-data/');
  });

  it('allows a hostname resolving to private IP when allowInternal is true', async () => {
    await expect(
      assertSafeUrl('http://internal.example/admin', {
        allowInternal: true,
        lookup: lookup({ 'internal.example': ['10.0.0.5'] }),
      }),
    ).resolves.toBe('http://internal.example/admin');
  });

  it('still rejects non-http schemes even with allowInternal', async () => {
    await expect(assertSafeUrl('file:///etc/passwd', { allowInternal: true })).rejects.toThrow(
      UnsafeUrlError,
    );
    await expect(assertSafeUrl('gopher://127.0.0.1/x', { allowInternal: true })).rejects.toThrow(
      UnsafeUrlError,
    );
  });

  it('still rejects loopback when allowInternal is false (default)', async () => {
    await expect(assertSafeUrl('http://127.0.0.1:8181/secret')).rejects.toThrow(UnsafeUrlError);
  });
});

describe('MCPHUB_ALLOWED_INTERNAL_HOSTS parsing', () => {
  it('splits, trims, lower-cases and de-duplicates entries', () => {
    expect(
      parseAllowedInternalHosts(' Mirrord.CICD2.getdeepin.org , internal.example ,, MIRRORD.cicd2.getdeepin.org. '),
    ).toEqual(['mirrord.cicd2.getdeepin.org', 'internal.example']);
  });

  it('keeps wildcards intact and tolerates URLs, ports and paths', () => {
    expect(
      parseAllowedInternalHosts(
        'https://*.corp.example:8443/api, mirrord-*.corp.example, 10.20.*.*, http://[fd00::1]:8080',
      ),
    ).toEqual(['*.corp.example', 'mirrord-*.corp.example', '10.20.*.*', 'fd00::1']);
  });

  it('returns an empty list for unset/empty/blank input', () => {
    expect(parseAllowedInternalHosts(undefined)).toEqual([]);
    expect(parseAllowedInternalHosts('')).toEqual([]);
    expect(parseAllowedInternalHosts(' , , ')).toEqual([]);
  });

  it('drops wildcard-only entries that would allowlist every host', () => {
    expect(parseAllowedInternalHosts('*, *.*, **, internal.example')).toEqual(['internal.example']);
  });
});

describe('isAllowedInternalHost', () => {
  it('matches an exact host case-insensitively and ignores a trailing dot', () => {
    expect(isAllowedInternalHost('Internal.Example', ['internal.example'])).toBe(true);
    expect(isAllowedInternalHost('internal.example.', ['internal.example'])).toBe(true);
  });

  it('supports a leading * wildcard for sub-domains without matching the apex', () => {
    const allowlist = parseAllowedInternalHosts('*.corp.example');

    expect(isAllowedInternalHost('a.corp.example', allowlist)).toBe(true);
    expect(isAllowedInternalHost('a.b.corp.example', allowlist)).toBe(true);
    expect(isAllowedInternalHost('corp.example', allowlist)).toBe(false);
  });

  it('anchors patterns so a wildcard cannot escape its own domain', () => {
    const allowlist = parseAllowedInternalHosts('*.corp.example');

    expect(isAllowedInternalHost('evilcorp.example', allowlist)).toBe(false);
    expect(isAllowedInternalHost('corp.example.evil.net', allowlist)).toBe(false);
    expect(isAllowedInternalHost('notcorp.example', allowlist)).toBe(false);
  });

  it('supports * in the middle of a pattern', () => {
    const allowlist = parseAllowedInternalHosts('mirrord-*.corp.example');

    expect(isAllowedInternalHost('mirrord-1.corp.example', allowlist)).toBe(true);
    expect(isAllowedInternalHost('mirrord-abc-2.corp.example', allowlist)).toBe(true);
    expect(isAllowedInternalHost('mirrord.corp.example', allowlist)).toBe(false);
  });

  it('supports * across labels and in IP-shaped patterns', () => {
    expect(isAllowedInternalHost('a.b.corp.example', parseAllowedInternalHosts('a.*.example'))).toBe(
      true,
    );
    expect(isAllowedInternalHost('10.20.64.64', parseAllowedInternalHosts('10.20.*.*'))).toBe(true);
    expect(isAllowedInternalHost('10.21.64.64', parseAllowedInternalHosts('10.20.*.*'))).toBe(false);
  });

  it('matches bracketed IPv6 hostnames', () => {
    expect(isAllowedInternalHost('[fd00::1]', parseAllowedInternalHosts('fd00::1'))).toBe(true);
  });

  it('treats regex metacharacters as literals', () => {
    const allowlist = parseAllowedInternalHosts('a+b.example');

    expect(isAllowedInternalHost('a+b.example', allowlist)).toBe(true);
    expect(isAllowedInternalHost('aab.example', allowlist)).toBe(false);
  });

  it('never allows anything with an empty allowlist', () => {
    expect(isAllowedInternalHost('internal.example', [])).toBe(false);
  });
});

describe('assertSafeUrl with the internal-host allowlist', () => {
  afterEach(() => {
    delete process.env[ALLOWED_INTERNAL_HOSTS_ENV_VAR];
  });

  it('allows an allowlisted hostname that resolves to a private IP', async () => {
    await expect(
      assertSafeUrl('http://mirrord.cicd2.getdeepin.org/mcp', {
        allowedInternalHosts: parseAllowedInternalHosts('*.getdeepin.org'),
        lookup: lookup({ 'mirrord.cicd2.getdeepin.org': ['10.20.64.64'] }),
      }),
    ).resolves.toBe('http://mirrord.cicd2.getdeepin.org/mcp');
  });

  it('allows an allowlisted IP literal', async () => {
    await expect(
      assertSafeUrl('http://10.20.64.64:8080/mcp', {
        allowedInternalHosts: parseAllowedInternalHosts('10.20.*.*'),
      }),
    ).resolves.toBe('http://10.20.64.64:8080/mcp');
  });

  it('still rejects an internal host outside the allowlist', async () => {
    await expect(
      assertSafeUrl('http://other.cicd2.getdeepin.org/mcp', {
        allowedInternalHosts: parseAllowedInternalHosts('mirrord.cicd2.getdeepin.org'),
        lookup: lookup({ 'other.cicd2.getdeepin.org': ['10.20.64.65'] }),
      }),
    ).rejects.toThrow(UnsafeUrlError);
  });

  it('still rejects the cloud metadata endpoint', async () => {
    await expect(
      assertSafeUrl('http://169.254.169.254/latest/meta-data/', {
        allowedInternalHosts: parseAllowedInternalHosts('*.getdeepin.org'),
      }),
    ).rejects.toThrow(UnsafeUrlError);
  });

  it('still rejects non-http schemes for an allowlisted host', async () => {
    await expect(
      assertSafeUrl('file://mirrord.cicd2.getdeepin.org/etc/passwd', {
        allowedInternalHosts: parseAllowedInternalHosts('*.getdeepin.org'),
      }),
    ).rejects.toThrow(UnsafeUrlError);
  });

  it('reads the allowlist from the environment by default', async () => {
    process.env[ALLOWED_INTERNAL_HOSTS_ENV_VAR] = '*.getdeepin.org';

    await expect(
      assertSafeUrl('http://mirrord.cicd2.getdeepin.org/mcp', {
        lookup: lookup({ 'mirrord.cicd2.getdeepin.org': ['10.20.64.64'] }),
      }),
    ).resolves.toBe('http://mirrord.cicd2.getdeepin.org/mcp');
  });

  it('lets a caller override the environment allowlist with an explicit list', async () => {
    process.env[ALLOWED_INTERNAL_HOSTS_ENV_VAR] = '*.getdeepin.org';

    await expect(
      assertSafeUrl('http://mirrord.cicd2.getdeepin.org/mcp', {
        allowedInternalHosts: [],
        lookup: lookup({ 'mirrord.cicd2.getdeepin.org': ['10.20.64.64'] }),
      }),
    ).rejects.toThrow(UnsafeUrlError);
  });

  it('still allows a public host that is not in the allowlist', async () => {
    process.env[ALLOWED_INTERNAL_HOSTS_ENV_VAR] = 'mirrord.cicd2.getdeepin.org';

    await expect(
      assertSafeUrl('http://public.example/mcp', {
        lookup: lookup({ 'public.example': ['93.184.216.34'] }),
      }),
    ).resolves.toBe('http://public.example/mcp');
  });
});

describe('createRedirectValidatingFetch', () => {
  const makeResponse = (status: number, location?: string, body: BodyInit = ''): Response => {
    const headers = new Headers();
    if (location) headers.set('location', location);
    const nullBody = status === 204 || status === 304;
    return new Response(nullBody ? null : body, { status, headers });
  };

  it('rejects an internal initial URL without calling base fetch', async () => {
    const baseFetch = jest.fn(async () => makeResponse(200));
    const safeFetch = createRedirectValidatingFetch(baseFetch as unknown as typeof fetch, false);

    await expect(safeFetch('http://127.0.0.1:8181/secret')).rejects.toThrow(UnsafeUrlError);
    expect(baseFetch).not.toHaveBeenCalled();
  });

  it('uses the supplied DNS lookup for the initial URL and redirects', async () => {
    const lookup = jest.fn(async () => ['93.184.216.34']);
    const baseFetch = jest
      .fn<typeof fetch>()
      .mockResolvedValueOnce(makeResponse(302, 'https://redirect.example/next') as Response)
      .mockResolvedValueOnce(makeResponse(200) as Response);
    const safeFetch = createRedirectValidatingFetch(baseFetch, false, lookup);

    await expect(safeFetch('https://client.example/start')).resolves.toMatchObject({ status: 200 });
    expect(lookup).toHaveBeenCalledWith('client.example');
    expect(lookup).toHaveBeenCalledWith('redirect.example');
  });

  it('returns the response directly for a non-redirect (2xx)', async () => {
    const baseFetch = jest.fn(async () => makeResponse(200));
    const safeFetch = createRedirectValidatingFetch(baseFetch as unknown as typeof fetch, false);
    const res = await safeFetch('http://8.8.8.8/api');
    expect(res.status).toBe(200);
    expect(baseFetch).toHaveBeenCalledTimes(1);
  });

  it('follows a redirect to a safe Location and returns the final response', async () => {
    const baseFetch = jest
      .fn<typeof fetch>()
      .mockResolvedValueOnce(makeResponse(302, 'http://8.8.8.8/next') as Response)
      .mockResolvedValueOnce(makeResponse(200, undefined, 'done') as Response);
    const safeFetch = createRedirectValidatingFetch(baseFetch, false);
    const res = await safeFetch('http://8.8.8.8/start');
    expect(res.status).toBe(200);
    expect(baseFetch).toHaveBeenCalledTimes(2);
    expect(baseFetch).toHaveBeenNthCalledWith(
      1,
      'http://8.8.8.8/start',
      expect.objectContaining({ redirect: 'manual' }),
    );
    expect(baseFetch).toHaveBeenNthCalledWith(
      2,
      'http://8.8.8.8/next',
      expect.objectContaining({ redirect: 'manual' }),
    );
  });

  it('rejects a redirect to an internal IP Location without following', async () => {
    const baseFetch = jest
      .fn<typeof fetch>()
      .mockResolvedValueOnce(makeResponse(302, 'http://127.0.0.1:8181/secret') as Response);
    const safeFetch = createRedirectValidatingFetch(baseFetch, false);
    await expect(safeFetch('http://8.8.8.8/start')).rejects.toThrow(UnsafeUrlError);
    expect(baseFetch).toHaveBeenCalledTimes(1);
  });

  it('allows a redirect to an internal IP when allowInternal is true', async () => {
    const baseFetch = jest
      .fn<typeof fetch>()
      .mockResolvedValueOnce(makeResponse(302, 'http://127.0.0.1:8181/secret') as Response)
      .mockResolvedValueOnce(makeResponse(200, undefined, 'internal') as Response);
    const safeFetch = createRedirectValidatingFetch(baseFetch, true);
    const res = await safeFetch('http://8.8.8.8/start');
    expect(res.status).toBe(200);
    expect(baseFetch).toHaveBeenCalledTimes(2);
  });

  it('rejects the metadata endpoint on redirect', async () => {
    const baseFetch = jest
      .fn<typeof fetch>()
      .mockResolvedValueOnce(
        makeResponse(302, 'http://169.254.169.254/latest/meta-data/') as Response,
      );
    const safeFetch = createRedirectValidatingFetch(baseFetch, false);
    await expect(safeFetch('http://8.8.8.8/start')).rejects.toThrow(UnsafeUrlError);
  });

  it('rejects after too many redirects (>5 hops)', async () => {
    const baseFetch = jest
      .fn<typeof fetch>()
      .mockImplementation(async (url: URL | RequestInfo) =>
        makeResponse(302, `${url.toString()}/x`),
      );
    const safeFetch = createRedirectValidatingFetch(baseFetch, false);
    await expect(safeFetch('http://8.8.8.8/loop')).rejects.toThrow(UnsafeUrlError);
    expect(baseFetch).toHaveBeenCalledTimes(6);
  });

  it('returns the response when a 3xx has no Location header', async () => {
    const baseFetch = jest.fn<typeof fetch>().mockResolvedValueOnce(makeResponse(302) as Response);
    const safeFetch = createRedirectValidatingFetch(baseFetch, false);
    const res = await safeFetch('http://8.8.8.8/start');
    expect(res.status).toBe(302);
    expect(baseFetch).toHaveBeenCalledTimes(1);
  });

  it('resolves a relative Location against the current URL', async () => {
    const baseFetch = jest
      .fn<typeof fetch>()
      .mockResolvedValueOnce(makeResponse(302, '/next') as Response)
      .mockResolvedValueOnce(makeResponse(200, undefined, 'done') as Response);
    const safeFetch = createRedirectValidatingFetch(baseFetch, false);
    const res = await safeFetch('http://8.8.8.8/start');
    expect(res.status).toBe(200);
    expect(baseFetch).toHaveBeenNthCalledWith(2, 'http://8.8.8.8/next', expect.anything());
  });

  it('does not treat 304 Not Modified as a redirect', async () => {
    const baseFetch = jest.fn<typeof fetch>().mockResolvedValueOnce(makeResponse(304) as Response);
    const safeFetch = createRedirectValidatingFetch(baseFetch, false);
    const res = await safeFetch('http://8.8.8.8/start');
    expect(res.status).toBe(304);
    expect(baseFetch).toHaveBeenCalledTimes(1);
  });

  it('follows a redirect to an allowlisted internal host', async () => {
    process.env[ALLOWED_INTERNAL_HOSTS_ENV_VAR] = '*.getdeepin.org';
    const baseFetch = jest
      .fn<typeof fetch>()
      .mockResolvedValueOnce(
        makeResponse(302, 'http://mirrord.cicd2.getdeepin.org/mcp') as Response,
      )
      .mockResolvedValueOnce(makeResponse(200, undefined, 'internal') as Response);
    const safeFetch = createRedirectValidatingFetch(baseFetch, false);

    const res = await safeFetch('http://8.8.8.8/start');

    expect(res.status).toBe(200);
    expect(baseFetch).toHaveBeenCalledTimes(2);
  });

  it('rejects a redirect to an internal host outside the allowlist', async () => {
    process.env[ALLOWED_INTERNAL_HOSTS_ENV_VAR] = 'mirrord.cicd2.getdeepin.org';
    const baseFetch = jest
      .fn<typeof fetch>()
      .mockResolvedValueOnce(
        makeResponse(302, 'http://other.cicd2.getdeepin.org/mcp') as Response,
      );
    const safeFetch = createRedirectValidatingFetch(baseFetch, false, async () => ['10.20.64.65']);

    await expect(safeFetch('http://8.8.8.8/start')).rejects.toThrow(UnsafeUrlError);
    expect(baseFetch).toHaveBeenCalledTimes(1);
  });

  afterEach(() => {
    delete process.env[ALLOWED_INTERNAL_HOSTS_ENV_VAR];
  });
});
