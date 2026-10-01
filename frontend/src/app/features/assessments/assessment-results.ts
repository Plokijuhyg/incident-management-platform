export type Observation = Record<string, unknown>;
export const severities = ['Critical', 'High', 'Medium', 'Low', 'Informational'] as const;
export function parseObservations(json?: string | null): Observation[] {
  try {
    const value: unknown = JSON.parse(json || '[]');
    return Array.isArray(value) ? value.filter((item): item is Observation => item !== null && typeof item === 'object' && !Array.isArray(item)) : [];
  } catch { return []; }
}
export function filterObservations(rows: Observation[], kind: string, severity: string, search: string): Observation[] {
  const query = search.trim().toLowerCase();
  const rank = (value: unknown) => { const index = severities.findIndex(s => s === value); return index < 0 ? 5 : index; };
  return rows.filter(row =>
    (kind === 'all' || (kind === 'findings' ? row['kind'] === 'Finding' : row['kind'] !== 'Finding')) &&
    (!severity || row['severity'] === severity) &&
    (!query || ['title', 'service', 'cve', 'endpoint', 'port', 'tool', 'product'].some(key => String(row[key] ?? '').toLowerCase().includes(query)))
  ).sort((a, b) => rank(a['severity']) - rank(b['severity']));
}
