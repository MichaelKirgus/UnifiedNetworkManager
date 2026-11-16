// @vitest-environment jsdom
import { describe, it, expect, vi, afterEach } from 'vitest';
import { render, screen, fireEvent, cleanup } from '@testing-library/react';
import { PageTabs } from './PageTabs';

const tabs = [
  { id: 'a' as const, label: 'Alpha', count: 3 },
  { id: 'b' as const, label: 'Beta' },
];

describe('PageTabs', () => {
  afterEach(cleanup);

  it('renders every tab and marks the active one with aria-selected', () => {
    render(<PageTabs tabs={tabs} value="a" onChange={() => undefined} />);
    expect(screen.getByRole('tablist')).toBeTruthy();
    expect(screen.getByRole('tab', { name: /Alpha/ }).getAttribute('aria-selected')).toBe('true');
    expect(screen.getByRole('tab', { name: 'Beta' }).getAttribute('aria-selected')).toBe('false');
  });

  it('calls onChange with the clicked tab id', () => {
    const onChange = vi.fn();
    render(<PageTabs tabs={tabs} value="a" onChange={onChange} />);
    fireEvent.click(screen.getByRole('tab', { name: 'Beta' }));
    expect(onChange).toHaveBeenCalledWith('b');
  });

  it('renders the count badge only when a number is provided', () => {
    render(<PageTabs tabs={tabs} value="a" onChange={() => undefined} />);
    // Alpha carries count 3 → its accessible name includes "3"; Beta has no badge.
    expect(screen.getByRole('tab', { name: /Alpha.*3/ })).toBeTruthy();
    expect(screen.getByRole('tab', { name: 'Beta' })).toBeTruthy();
  });

  it('renders the actions slot when provided and omits it otherwise', () => {
    const { unmount } = render(
      <PageTabs tabs={tabs} value="a" onChange={() => undefined} actions={<button type="button">New thing</button>} />
    );
    expect(screen.getByRole('button', { name: 'New thing' })).toBeTruthy();
    unmount();
    cleanup();
    render(<PageTabs tabs={tabs} value="a" onChange={() => undefined} />);
    expect(screen.queryByRole('button', { name: 'New thing' })).toBeNull();
  });
});
