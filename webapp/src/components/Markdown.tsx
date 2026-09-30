import { ReactNode } from 'react';

/**
 * Minimal, dependency-free markdown renderer for plugin-provided documentation
 * (built-in docs + LICENSE.md served through the API's asset proxy). Supports
 * the subset that appears in real-world READMEs: headings, paragraphs, inline
 * code / bold / italic / links, fenced code blocks, unordered/ordered lists,
 * blockquotes and horizontal rules. All text is rendered as React strings —
 * never via innerHTML — so untrusted plugin content cannot inject markup.
 */

/** Renders one line of inline markdown into React nodes (safe: no HTML injection). */
function renderInline(text: string): ReactNode[] {
  const nodes: ReactNode[] = [];
  const re = /(`[^`]+`)|(\[([^\]]+)\]\(([^)\s]+)\))|(\*\*([^*]+)\*\*)|(__([^_]+)__)|(\*([^*\s][^*]*)\*)/g;
  let last = 0;
  let m: RegExpExecArray | null;
  let i = 0;
  while ((m = re.exec(text))) {
    if (m.index > last) nodes.push(text.slice(last, m.index));
    const key = `i${i++}`;
    if (m[1]) {
      nodes.push(
        <code key={key} className="rounded bg-muted px-1 py-0.5 font-mono text-[0.85em]">
          {m[1].slice(1, -1)}
        </code>
      );
    } else if (m[2]) {
      const href = m[4];
      // Only allow http(s) links — plugin docs must not open javascript: URLs.
      const safe = /^https?:\/\//i.test(href);
      nodes.push(
        safe ? (
          <a key={key} href={href} target="_blank" rel="noreferrer" className="text-accent-indigo underline">
            {m[3]}
          </a>
        ) : (
          m[3]
        )
      );
    } else if (m[5]) {
      nodes.push(<strong key={key}>{m[6]}</strong>);
    } else if (m[7]) {
      nodes.push(<strong key={key}>{m[8]}</strong>);
    } else if (m[9]) {
      nodes.push(<em key={key}>{m[10]}</em>);
    }
    last = m.index + m[0].length;
  }
  if (last < text.length) nodes.push(text.slice(last));
  return nodes;
}

/** Renders a full markdown document into React nodes. */
export function renderMarkdown(md: string): ReactNode[] {
  const lines = md.replace(/\r\n/g, '\n').split('\n');
  const out: ReactNode[] = [];
  let i = 0;
  let key = 0;

  while (i < lines.length) {
    const line = lines[i];

    // Fenced code block.
    if (/^```/.test(line)) {
      const buf: string[] = [];
      i += 1;
      while (i < lines.length && !/^```/.test(lines[i])) {
        buf.push(lines[i]);
        i += 1;
      }
      i += 1; // skip closing fence
      out.push(
        <pre key={key++} className="my-2 overflow-x-auto rounded-md bg-muted p-3 font-mono text-xs leading-relaxed">
          {buf.join('\n')}
        </pre>
      );
      continue;
    }

    // Heading.
    const h = line.match(/^(#{1,6})\s+(.*)$/);
    if (h) {
      const level = h[1].length;
      const content = renderInline(h[2]);
      out.push(
        level === 1 ? (
          <h1 key={key++} className="mb-2 mt-4 text-lg font-semibold first:mt-0">{content}</h1>
        ) : level === 2 ? (
          <h2 key={key++} className="mb-2 mt-4 text-base font-semibold first:mt-0">{content}</h2>
        ) : level === 3 ? (
          <h3 key={key++} className="mb-1.5 mt-3 text-sm font-semibold first:mt-0">{content}</h3>
        ) : (
          <h4 key={key++} className="mb-1 mt-2 text-sm font-medium first:mt-0">{content}</h4>
        )
      );
      i += 1;
      continue;
    }

    // Horizontal rule.
    if (/^\s*(---+|\*\*\*+)\s*$/.test(line)) {
      out.push(<hr key={key++} className="my-3 border-border" />);
      i += 1;
      continue;
    }

    // Unordered list (group consecutive items).
    if (/^\s*[-*+]\s+/.test(line)) {
      const items: string[] = [];
      while (i < lines.length && /^\s*[-*+]\s+/.test(lines[i])) {
        items.push(lines[i].replace(/^\s*[-*+]\s+/, ''));
        i += 1;
      }
      out.push(
        <ul key={key++} className="my-2 list-disc space-y-0.5 pl-5">
          {items.map((it, j) => (
            <li key={j}>{renderInline(it)}</li>
          ))}
        </ul>
      );
      continue;
    }

    // Ordered list (group consecutive items).
    if (/^\s*\d+[.)]\s+/.test(line)) {
      const items: string[] = [];
      while (i < lines.length && /^\s*\d+[.)]\s+/.test(lines[i])) {
        items.push(lines[i].replace(/^\s*\d+[.)]\s+/, ''));
        i += 1;
      }
      out.push(
        <ol key={key++} className="my-2 list-decimal space-y-0.5 pl-5">
          {items.map((it, j) => (
            <li key={j}>{renderInline(it)}</li>
          ))}
        </ol>
      );
      continue;
    }

    // Blockquote (group consecutive lines).
    if (/^\s*>\s?/.test(line)) {
      const buf: string[] = [];
      while (i < lines.length && /^\s*>\s?/.test(lines[i])) {
        buf.push(lines[i].replace(/^\s*>\s?/, ''));
        i += 1;
      }
      out.push(
        <blockquote key={key++} className="my-2 border-l-2 border-border pl-3 text-secondary">
          {buf.map((b, j) => (
            <p key={j}>{renderInline(b)}</p>
          ))}
        </blockquote>
      );
      continue;
    }

    // Blank line.
    if (line.trim() === '') {
      i += 1;
      continue;
    }

    // Paragraph — consume consecutive non-special lines.
    const buf: string[] = [line];
    i += 1;
    while (
      i < lines.length &&
      lines[i].trim() !== '' &&
      !/^(#{1,6})\s/.test(lines[i]) &&
      !/^```/.test(lines[i]) &&
      !/^\s*[-*+]\s+/.test(lines[i]) &&
      !/^\s*\d+[.)]\s+/.test(lines[i]) &&
      !/^\s*>\s?/.test(lines[i]) &&
      !/^\s*(---+|\*\*\*+)\s*$/.test(lines[i])
    ) {
      buf.push(lines[i]);
      i += 1;
    }
    out.push(
      <p key={key++} className="my-2 leading-relaxed">
        {renderInline(buf.join(' '))}
      </p>
    );
  }

  return out;
}

/** Renders markdown text inside a scrollable container. */
export function Markdown({ text, className = '' }: { text: string; className?: string }) {
  return <div className={`text-sm text-foreground ${className}`}>{renderMarkdown(text)}</div>;
}
