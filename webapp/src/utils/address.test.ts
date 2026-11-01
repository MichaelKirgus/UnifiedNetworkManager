import { describe, it, expect } from 'vitest';
import { isIpLiteral, isValidAddress, addressError, ipScope, ipScopeGroup } from './address';

describe('isIpLiteral', () => {
  it('accepts IPv4 literals', () => {
    expect(isIpLiteral('192.168.1.1')).toBe(true);
    expect(isIpLiteral('0.0.0.0')).toBe(true);
    expect(isIpLiteral('255.255.255.255')).toBe(true);
  });

  it('rejects out-of-range IPv4 octets', () => {
    expect(isIpLiteral('256.1.1.1')).toBe(false);
    expect(isIpLiteral('1.2.3.999')).toBe(false);
  });

  it('accepts full and compressed IPv6 literals, with optional zone id', () => {
    expect(isIpLiteral('2001:db8::1')).toBe(true);
    expect(isIpLiteral('fe80::1%eth0')).toBe(true);
    expect(isIpLiteral('::1')).toBe(true);
  });

  it('rejects malformed IPv6 (multiple :: or bad groups)', () => {
    expect(isIpLiteral('2001:db8::1::2')).toBe(false);
    expect(isIpLiteral('zzzz::1')).toBe(false);
  });

  it('returns false for DNS names', () => {
    expect(isIpLiteral('router.local')).toBe(false);
  });
});

describe('isValidAddress', () => {
  it('accepts IPv4, IPv6 and DNS names (trimmed)', () => {
    expect(isValidAddress('10.0.0.5')).toBe(true);
    expect(isValidAddress('fe80::1%en1')).toBe(true);
    expect(isValidAddress('  gateway.local ')).toBe(true);
  });

  it('rejects schemes, empty strings and non-strings', () => {
    expect(isValidAddress('https://example.com')).toBe(false);
    expect(isValidAddress('ssh://host:22')).toBe(false);
    expect(isValidAddress('   ')).toBe(false);
    expect(isValidAddress(42)).toBe(false);
    expect(isValidAddress(null)).toBe(false);
  });

  it('rejects hostnames with invalid labels', () => {
    expect(isValidAddress('-leading-hyphen.local')).toBe(false);
    expect(isValidAddress('trailing-hyphen-.local')).toBe(false);
  });
});

describe('addressError', () => {
  it('returns null for valid addresses and a message otherwise', () => {
    expect(addressError('10.0.0.5')).toBeNull();
    expect(addressError('https://x')).toMatch(/no scheme/);
  });
});

describe('ipScope / ipScopeGroup', () => {
  it('classifies IPv4 scopes', () => {
    expect(ipScope('192.168.1.10')).toBe('private');
    expect(ipScope('169.254.1.1')).toBe('link-local');
    expect(ipScope('8.8.8.8')).toBe('public');
  });

  it('classifies IPv6 ULA vs GUA distinctly (documentation range is unscoped)', () => {
    expect(ipScope('fc00::1')).toBe('ula');
    expect(ipScope('2606:4700:4700::1111')).toBe('gua');
    expect(ipScope('2001:db8::1')).toBeNull(); // 2001:db8::/32 is documentation space
  });

  it('returns null for loopback / unclassifiable input', () => {
    expect(ipScope('127.0.0.1')).toBeNull();
    expect(ipScope('not-an-ip')).toBeNull();
  });

  it('collapses ULA→private and GUA→public in the coarse group', () => {
    expect(ipScopeGroup('fc00::1')).toBe('private');
    expect(ipScopeGroup('2606:4700:4700::1111')).toBe('public');
    expect(ipScopeGroup('192.168.1.10')).toBe('private');
  });

  it('ignores the CIDR prefix and uses only the network address', () => {
    expect(ipScope('10.40.0.0/16')).toBe('private');
    expect(ipScopeGroup('2606:4700:4700::/48')).toBe('public');
  });
});
