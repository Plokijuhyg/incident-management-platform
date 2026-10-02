import { UrlMatchResult, UrlSegment } from '@angular/router';

/**
 * Matches both `alerts` and `alerts/:id` with one route config, so Angular reuses the
 * queue component when an alert is opened or closed: the list, filters and scroll stay put.
 * Kept out of alert-queue.ts so the route table does not pull the page into the main bundle.
 */
export function alertsMatcher(segments: UrlSegment[]): UrlMatchResult | null {
  if (segments[0]?.path !== 'alerts' || segments.length > 2) return null;
  return { consumed: segments, posParams: segments[1] ? { id: segments[1] } : {} };
}
