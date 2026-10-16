// Shared, presentation-only formatting for raw tool / gateway output. Used by both the Inspect
// Assessment evidence view and the AI Orchestrator transcript. It never interprets results — it
// only makes them readable, and is robust to JSON that is truncated or escaped (the orchestrator
// stores a capped copy): it strips ANSI codes, pulls nmap port/service data out by regex (works on
// clean, JSON-escaped or truncated XML), breaks multi-tool results into per-tool sections, extracts
// stdout/stderr from tool-result JSON, and pretty-prints anything else.

function stripAnsi(s: string): string {
  return s
    .replace(/\u001b\[[0-9;]*[A-Za-z]/g, '')
    .replace(/\u001b[()][AB0-2]/g, '')
    .replace(/\r/g, '')
    .replace(/\n{3,}/g, '\n\n')
    .trim();
}

// Extract a readable host + open-port/service table from nmap XML. Uses regex (not a DOM parser) so
// it still works when the XML is JSON-escaped (\" , \n) or was truncated mid-document.
function formatNmapTable(raw: string): string | null {
  const t = raw.replace(/\\"/g, '"').replace(/\\n/g, '\n').replace(/\\\//g, '/');
  if (!/portid="\d+"/.test(t)) return null;
  const host = /<address addr="([\d.]+)"/.exec(t)?.[1] ?? /addr="([\d.]+)"/.exec(t)?.[1] ?? '';
  const rows: string[] = [];
  for (const chunk of t.split('<port ').slice(1)) {
    const scope = chunk.includes('</port>') ? chunk.slice(0, chunk.indexOf('</port>')) : chunk;
    const portid = /portid="(\d+)"/.exec(scope)?.[1];
    const state = /<state state="(\w+)"/.exec(scope)?.[1] ?? '';
    if (!portid || state !== 'open') continue;
    const proto = /protocol="(\w+)"/.exec(chunk)?.[1] ?? 'tcp';
    const name = /<service name="([^"]+)"/.exec(scope)?.[1] ?? '';
    const product = /product="([^"]+)"/.exec(scope)?.[1] ?? '';
    const version = /\sversion="([^"]+)"/.exec(scope)?.[1] ?? '';
    rows.push(
      (portid + '/' + proto).padEnd(10) + state.padEnd(8) + name.padEnd(16) + [product, version].filter(Boolean).join(' '),
    );
  }
  if (!rows.length) return null;
  const out = host ? ['Host ' + host, ''] : [];
  out.push('PORT'.padEnd(10) + 'STATE'.padEnd(8) + 'SERVICE'.padEnd(16) + 'VERSION', ...rows);
  return out.join('\n');
}

function asObj(v: unknown): Record<string, unknown> | null {
  return v !== null && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : null;
}

// Render known gateway/tool JSON shapes readably; return null to let the caller pretty-print.
function renderJson(parsed: unknown): string | null {
  let d = asObj(parsed);
  if (d && asObj(d['result'])) d = asObj(d['result']);
  if (!d) return null;

  if (Array.isArray(d['steps'])) {
    const parts = (d['steps'] as unknown[]).map((s) => {
      const so = asObj(s);
      if (!so) return formatToolOutput(s);
      const head = '━━━━━ ' + (so['tool'] ?? 'tool') + (so['status'] ? ' (' + so['status'] + ')' : '') + ' ━━━━━';
      return head + '\n' + formatToolOutput(so['evidence'] ?? so['xml'] ?? so['output'] ?? JSON.stringify(so));
    });
    if (parts.length) return parts.join('\n\n');
  }

  if ('stdout' in d || 'stderr' in d || 'error' in d) {
    const sections: string[] = [];
    const meta: string[] = [];
    if ('return_code' in d) meta.push('exit code: ' + d['return_code']);
    if (d['execution_time'] != null) meta.push('time: ' + Math.round(Number(d['execution_time'])) + 's');
    if (d['timed_out']) meta.push('TIMED OUT');
    if (d['success'] === false) meta.push('FAILED');
    if (meta.length) sections.push(meta.join('   ·   '));
    const stdoutRaw = String(d['stdout'] ?? d['output'] ?? d['xml'] ?? '');
    const out = formatNmapTable(stdoutRaw) ?? stripAnsi(stdoutRaw);
    const errout = stripAnsi(String(d['stderr'] ?? ''));
    const err = stripAnsi(String(d['error'] ?? ''));
    if (out) sections.push('──────── output ────────\n' + out);
    if (errout) sections.push('──────── diagnostics ────────\n' + errout);
    if (err) sections.push('──────── error ────────\n' + err);
    if (sections.length) return sections.join('\n\n');
  }

  return null;
}

export function formatToolOutput(value: unknown): string {
  if (value === null || value === undefined) return '';
  const raw = String(value).trim();

  // Clean JSON: use the structured renderer (per-tool sections, stdout/stderr, nmap).
  if ((raw.startsWith('{') && raw.endsWith('}')) || (raw.startsWith('[') && raw.endsWith(']'))) {
    try {
      const parsed: unknown = JSON.parse(raw);
      const r = renderJson(parsed);
      if (r) return r;
      // fall through to nmap salvage, then pretty JSON
      const nmap = formatNmapTable(raw);
      return nmap ?? JSON.stringify(parsed, null, 2);
    } catch {
      /* truncated/invalid JSON — salvage below */
    }
  }

  // nmap data anywhere (raw XML, escaped, or truncated JSON that could not be parsed).
  const nmap = formatNmapTable(raw);
  if (nmap) return nmap;

  return stripAnsi(raw);
}
