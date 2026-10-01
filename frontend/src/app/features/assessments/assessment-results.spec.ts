import { describe, expect, it } from 'vitest';
import { parseObservations, filterObservations } from './assessment-results';
describe('Assessment result review', () => {
  const rows = [
    { kind: 'Observed open service', port: '445', severity: 'Informational', service: 'SMB' },
    { kind: 'Finding', title: 'SMB scanner finding', cve: 'CVE-2017-0143', severity: 'High' },
    { kind: 'Finding', title: 'Header observation', tool: 'Nikto', severity: 'Informational' },
  ];
  it('keeps open services out of finding counts and filters without changing stored evidence', () => {
    expect(filterObservations(rows, 'findings', '', '')).toHaveLength(2);
    expect(filterObservations(rows, 'services', '', '')).toHaveLength(1);
    expect(filterObservations(rows, 'all', 'High', 'cve-2017')[0]['cve']).toBe('CVE-2017-0143');
    expect(rows[0]['port']).toBe('445');
  });
  it('sorts real severity and returns an empty filtered result without inventing findings', () => {
    expect(filterObservations(rows, 'all', '', '')[0]['severity']).toBe('High');
    expect(filterObservations(rows, 'findings', 'Critical', '')).toEqual([]);
  });
  it('tolerates absent and malformed historical results', () => {
    for (const value of ['null', '{}', 'invalid', '[null,4,[],"x"]']) expect(parseObservations(value)).toEqual([]);
    expect(parseObservations(JSON.stringify(rows))).toEqual(rows);
  });
});
