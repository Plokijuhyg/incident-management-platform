import { UpdateIncident } from '../models/operations';
import { HttpClient } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { map } from 'rxjs';
import { CreateIncident, IncidentDetail, IncidentSummary, Page } from '../models/api';

// MySQL datetime values may be serialized without a suffix; the API contract is UTC.
export function utcTimestamp(value: string): string {
  return /(?:Z|[+-]\d{2}:\d{2})$/i.test(value) ? value : `${value}Z`;
}
function normalizeDetail(value: IncidentDetail): IncidentDetail {
  const nullable = (date: string | null) => (date ? utcTimestamp(date) : null);
  return {
    ...value,
    createdAt: utcTimestamp(value.createdAt),
    updatedAt: utcTimestamp(value.updatedAt),
    occurredAt: nullable(value.occurredAt),
    detectedAt: nullable(value.detectedAt),
    triagedAt: nullable(value.triagedAt),
    containedAt: nullable(value.containedAt),
    resolvedAt: nullable(value.resolvedAt),
    closedAt: nullable(value.closedAt),
  };
}
@Injectable({ providedIn: 'root' })
export class Incidents {
  private readonly http = inject(HttpClient);
  /** `filters` are passed through as query parameters; empty values are dropped. */
  list(page = 1, pageSize = 25, filters: Record<string, string | number | boolean> = {}) {
    const params: Record<string, string | number | boolean> = { page, pageSize };
    for (const [key, value] of Object.entries(filters)) if (value !== '') params[key] = value;
    return this.http
      .get<Page<IncidentSummary>>('/api/incidents', { params })
      .pipe(
        map((result) => ({
          ...result,
          items: result.items.map((item) => ({ ...item, createdAt: utcTimestamp(item.createdAt) })),
        })),
      );
  }
  update(id: number, request: UpdateIncident) {
    return this.http
      .put<IncidentDetail>(`/api/incidents/${id}`, request)
      .pipe(map(normalizeDetail));
  }
  assign(id: number, assignedToId: number) {
    return this.http
      .post<IncidentDetail>(`/api/incidents/${id}/assign`, { assignedToId })
      .pipe(map(normalizeDetail));
  }
  changeStatus(id: number, status: number, note: string | null) {
    return this.http
      .post<IncidentDetail>(`/api/incidents/${id}/status`, { status, note })
      .pipe(map(normalizeDetail));
  }
  close(id: number, resolutionSummary: string) {
    return this.http
      .post<IncidentDetail>(`/api/incidents/${id}/close`, { resolutionSummary })
      .pipe(map(normalizeDetail));
  }
  detail(id: number) {
    return this.http.get<IncidentDetail>(`/api/incidents/${id}`).pipe(map(normalizeDetail));
  }
  create(request: CreateIncident) {
    return this.http.post<IncidentDetail>('/api/incidents', request).pipe(map(normalizeDetail));
  }
}
