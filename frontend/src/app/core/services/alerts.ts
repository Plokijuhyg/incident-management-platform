import { HttpClient } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { map } from 'rxjs';
import { AlertDetail, AlertSummary, IncidentDetail, Page } from '../models/api';
import { utcTimestamp } from './incidents';

function normalize<T extends AlertSummary>(alert: T): T {
  const detail = alert as T & Partial<AlertDetail>;
  return {
    ...alert,
    detectedAt: utcTimestamp(alert.detectedAt),
    ...(detail.receivedAt ? { receivedAt: utcTimestamp(detail.receivedAt) } : {}),
    ...(detail.triagedAt ? { triagedAt: utcTimestamp(detail.triagedAt) } : {}),
  };
}

@Injectable({ providedIn: 'root' })
export class Alerts {
  private readonly http = inject(HttpClient);
  /** `filters` are passed through as query parameters; empty values are dropped. */
  list(page = 1, pageSize = 25, filters: Record<string, string | number | boolean> = {}) {
    const params: Record<string, string | number | boolean> = { page, pageSize };
    for (const [key, value] of Object.entries(filters)) if (value !== '') params[key] = value;
    return this.http
      .get<Page<AlertSummary>>('/api/alerts', { params })
      .pipe(map((result) => ({ ...result, items: result.items.map(normalize) })));
  }
  detail(id: number) {
    return this.http.get<AlertDetail>(`/api/alerts/${id}`).pipe(map(normalize));
  }
  create(request: Record<string, unknown>) {
    return this.http.post<AlertDetail>('/api/alerts', request).pipe(map(normalize));
  }
  promote(id: number, request: { title: string; severity: number; priority: number; category: number }) {
    return this.http.post<IncidentDetail>(`/api/alerts/${id}/promote`, request);
  }
  falsePositive(id: number, reason: string) {
    return this.http.post<AlertDetail>(`/api/alerts/${id}/false-positive`, { reason }).pipe(map(normalize));
  }
}

/** Maps source-reported severity text onto the incident severity scale (Low..Critical). */
export function incidentSeverityFor(alertSeverity: string): number {
  switch (alertSeverity.trim().toLowerCase()) {
    case 'critical':
      return 3;
    case 'high':
      return 2;
    case 'low':
    case 'informational':
    case 'info':
      return 0;
    default:
      return 1;
  }
}
