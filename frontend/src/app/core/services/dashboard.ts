import { HttpClient } from '@angular/common/http';
import { inject, Injectable } from '@angular/core';
import { forkJoin, map } from 'rxjs';
import {
  CountBucket,
  DashboardMetrics,
  DashboardSummary,
  TechniqueCount,
  TimeBucket,
} from '../models/operations';
import { utcTimestamp } from './incidents';
@Injectable({ providedIn: 'root' })
export class DashboardApi {
  private readonly http = inject(HttpClient);
  load(days: number, interval: string) {
    const root = '/api/dashboard';
    return forkJoin({
      summary: this.http.get<DashboardSummary>(`${root}/summary`),
      severity: this.http.get<CountBucket[]>(`${root}/incidents-by-severity`),
      status: this.http.get<CountBucket[]>(`${root}/incidents-by-status`),
      category: this.http.get<CountBucket[]>(`${root}/incidents-by-category`),
      iocTypes: this.http.get<CountBucket[]>(`${root}/top-ioc-types`),
      techniques: this.http.get<TechniqueCount[]>(`${root}/top-mitre-techniques`, {
        params: { limit: 10 },
      }),
      timeline: this.http
        .get<TimeBucket[]>(`${root}/incidents-over-time`, { params: { days, interval } })
        .pipe(map((data) => data.map((row) => ({ ...row, start: utcTimestamp(row.start) })))),
      metrics: this.http.get<DashboardMetrics>(`${root}/metrics`, { params: { periodDays: days } }),
    });
  }
}
