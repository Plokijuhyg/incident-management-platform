import { HttpClient } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { map } from 'rxjs';
import { Page } from '../models/api';
import { LogDetail, LogSummary, LogSummaryStats } from '../models/logs';
import { utcTimestamp } from './incidents';

function normalize<T extends LogSummary>(log: T): T {
  return {
    ...log,
    eventTime: utcTimestamp(log.eventTime),
    receivedAt: utcTimestamp(log.receivedAt),
  };
}

@Injectable({ providedIn: 'root' })
export class Logs {
  private readonly http = inject(HttpClient);
  /** `filters` are passed through as query parameters; empty values are dropped. */
  list(page = 1, pageSize = 25, filters: Record<string, string | number | boolean> = {}) {
    const params: Record<string, string | number | boolean> = { page, pageSize };
    for (const [key, value] of Object.entries(filters)) if (value !== '') params[key] = value;
    return this.http
      .get<Page<LogSummary>>('/api/logs', { params })
      .pipe(map((result) => ({ ...result, items: result.items.map(normalize) })));
  }
  detail(id: number) {
    return this.http.get<LogDetail>(`/api/logs/${id}`).pipe(map(normalize));
  }
  summary() {
    return this.http.get<LogSummaryStats>('/api/logs/summary');
  }
}
