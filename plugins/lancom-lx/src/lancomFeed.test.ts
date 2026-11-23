/**
 * Unit tests for the LANCOM release feed (lancomFeed.ts). The pure helpers are
 * tested directly; fetchLxFwFeed() runs against a mocked web-fetch broker — no
 * real egress in unit tests.
 */

jest.mock('@unm/plugin-sdk', () => {
  const actual = jest.requireActual('@unm/plugin-sdk');
  return { ...actual, webFetchViaApi: jest.fn() };
});

import { webFetchViaApi } from '@unm/plugin-sdk';
import { clearFeedCache, feedListingUrl, fetchLxFwFeed, parseLxFwListing, pickNewestLxFw } from './lancomFeed';

const mockFetch = webFetchViaApi as jest.MockedFunction<typeof webFetchViaApi>;

/** Real autoindex HTML captured from ftp.lancom.de/LANCOM-Releases/LC-LX-6500/ (2026-11-23). */
const REAL_LISTING = `<html>
<head><title>Index of /LANCOM-Releases/LC-LX-6500/</title></head>
<body>
<h1>Index of /LANCOM-Releases/LC-LX-6500/</h1><hr><pre><a href="../">../</a>
<a href="LC-LX-6500-7.20.0192-RU1.mib">LC-LX-6500-7.20.0192-RU1.mib</a>         
              13-Nov-2026 20:28              364316
<a href="LC-LX-6500-7.20.0192-RU1.upx">LC-LX-6500-7.20.0192-RU1.upx</a>         
              13-Nov-2026 20:28            70288610
</pre><hr></body>
</html>`;

describe('parseLxFwListing', () => {
  it('extracts .upx entries with sizes from a real autoindex listing', () => {
    expect(parseLxFwListing(REAL_LISTING)).toEqual([
      { fileName: 'LC-LX-6500-7.20.0192-RU1.upx', sizeBytes: 70_288_610 },
    ]);
  });

  it('ignores non-.upx entries (.mib, parent dir)', () => {
    const html = '<pre><a href="../">../</a>\n<a href="LC-LX-6500-7.20.0192-RU1.mib">x</a> 13-Nov-2026 20:28 364316\n</pre>';
    expect(parseLxFwListing(html)).toEqual([]);
  });

  it('returns [] for non-listing content (404 pages, error bodies)', () => {
    expect(parseLxFwListing('<html><body>404 Not Found</body></html>')).toEqual([]);
    expect(parseLxFwListing('')).toEqual([]);
  });

  it('collects multiple .upx entries', () => {
    const html = [
      '<pre>',
      '<a href="LC-LX-6500-7.14.0036RU1.upx">LC-LX-6500-7.14.0036RU1.upx</a> 01-Jan-2026 10:00 69000000',
      '<a href="LC-LX-6500-7.20.0192-RU1.upx">LC-LX-6500-7.20.0192-RU1.upx</a> 13-Nov-2026 20:28 70288610',
      '</pre>',
    ].join('\n');
    expect(parseLxFwListing(html)).toHaveLength(2);
  });
});

describe('pickNewestLxFw', () => {
  it('builds the entry with version, size and absolute URL', () => {
    const entries = parseLxFwListing(REAL_LISTING);
    expect(pickNewestLxFw(entries, 'https://ftp.lancom.de/LANCOM-Releases/LC-LX-6500/')).toEqual({
      fileName: 'LC-LX-6500-7.20.0192-RU1.upx',
      version: '7.20.0192-RU1',
      sizeBytes: 70_288_610,
      url: 'https://ftp.lancom.de/LANCOM-Releases/LC-LX-6500/LC-LX-6500-7.20.0192-RU1.upx',
    });
  });

  it('picks the newest version when a folder holds several images', () => {
    const entries = [
      { fileName: 'LC-LX-6500-7.14.0036RU1.upx', sizeBytes: 69_000_000 },
      { fileName: 'LC-LX-6500-7.20.0192-RU1.upx', sizeBytes: 70_288_610 },
    ];
    expect(pickNewestLxFw(entries, 'https://example.test/LC-LX-6500/')?.version).toBe('7.20.0192-RU1');
  });

  it('skips non-conventional names and returns null when nothing qualifies', () => {
    expect(pickNewestLxFw([{ fileName: 'weird.upx', sizeBytes: 1 }], 'https://example.test/')).toBeNull();
    expect(pickNewestLxFw([], 'https://example.test/')).toBeNull();
  });
});

describe('feedListingUrl', () => {
  it('points at the per-model folder under the release base', () => {
    // FEED_BASE_URL defaults to https://ftp.lancom.de/LANCOM-Releases (no env override in tests).
    expect(feedListingUrl('6500')).toBe('https://ftp.lancom.de/LANCOM-Releases/LC-LX-6500/');
  });
});

describe('fetchLxFwFeed', () => {
  beforeEach(() => {
    clearFeedCache();
    mockFetch.mockReset();
  });

  it('returns the newest entry for a 200 listing and caches it (one broker call per TTL window)', async () => {
    mockFetch.mockResolvedValue({ bytes: Buffer.from(REAL_LISTING), status: 200, contentType: 'text/html' });
    const first = await fetchLxFwFeed('6500');
    expect(first?.version).toBe('7.20.0192-RU1');
    const second = await fetchLxFwFeed('6500');
    expect(second).toEqual(first);
    expect(mockFetch).toHaveBeenCalledTimes(1); // second call served from cache
  });

  it('returns null for a 404 (model not published) and caches the negative', async () => {
    mockFetch.mockResolvedValue({ bytes: Buffer.from('<html>404</html>'), status: 404, contentType: 'text/html' });
    expect(await fetchLxFwFeed('9999')).toBeNull();
    expect(await fetchLxFwFeed('9999')).toBeNull();
    expect(mockFetch).toHaveBeenCalledTimes(1);
  });

  it('returns null for a 200 listing without any .upx', async () => {
    mockFetch.mockResolvedValue({ bytes: Buffer.from('<pre><a href="../">../</a></pre>'), status: 200, contentType: 'text/html' });
    expect(await fetchLxFwFeed('6500')).toBeNull();
  });

  it('throws on non-2xx/404 statuses without caching', async () => {
    mockFetch.mockResolvedValue({ bytes: Buffer.from('busy'), status: 503, contentType: 'text/plain' });
    await expect(fetchLxFwFeed('6500')).rejects.toThrow(/HTTP 503/);
    // Not cached — the next call retries.
    mockFetch.mockResolvedValue({ bytes: Buffer.from(REAL_LISTING), status: 200, contentType: 'text/html' });
    expect((await fetchLxFwFeed('6500'))?.version).toBe('7.20.0192-RU1');
    expect(mockFetch).toHaveBeenCalledTimes(2);
  });

  it('rethrows broker transport failures without caching', async () => {
    mockFetch.mockRejectedValue(new Error('web-fetch broker failed: no provider online'));
    await expect(fetchLxFwFeed('6500')).rejects.toThrow(/no provider online/);
    mockFetch.mockResolvedValue({ bytes: Buffer.from(REAL_LISTING), status: 200, contentType: 'text/html' });
    expect((await fetchLxFwFeed('6500'))?.version).toBe('7.20.0192-RU1');
    expect(mockFetch).toHaveBeenCalledTimes(2);
  });

  it('passes a bounded timeout + maxBytes to the broker', async () => {
    mockFetch.mockResolvedValue({ bytes: Buffer.from(REAL_LISTING), status: 200, contentType: 'text/html' });
    await fetchLxFwFeed('6500');
    expect(mockFetch).toHaveBeenCalledWith(expect.objectContaining({ url: feedListingUrl('6500'), timeoutMs: 15_000, maxBytes: 1024 * 1024 }));
  });
});
