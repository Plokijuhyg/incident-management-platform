import { utcTimestamp } from './incidents';
describe('UTC API timestamps', () => {
  it('interprets unsuffixed MySQL values as UTC and preserves explicit timezones', () => {
    expect(utcTimestamp('2026-09-24T12:00:00')).toBe('2026-09-24T12:00:00Z');
    expect(utcTimestamp('2026-09-24T12:00:00Z')).toBe('2026-09-24T12:00:00Z');
    expect(utcTimestamp('2026-09-24T12:00:00+03:00')).toBe('2026-09-24T12:00:00+03:00');
  });
});
