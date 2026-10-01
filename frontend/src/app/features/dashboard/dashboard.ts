import { InfoPopup } from '../../shared/components/detail-modal';
import { DatePipe, DecimalPipe } from '@angular/common';
import { Component, inject } from '@angular/core';
import { toSignal } from '@angular/core/rxjs-interop';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import {
  BehaviorSubject,
  Subject,
  catchError,
  combineLatest,
  map,
  merge,
  timer,
  filter,
  scan,
  of,
  switchMap,
} from 'rxjs';
import { Auth } from '../../core/services/auth';
import { DashboardApi } from '../../core/services/dashboard';
import { apiErrors } from '../../core/services/api-errors';
import { DashboardMetrics, TimeBucket } from '../../core/models/operations';
import { ErrorNotice } from '../../shared/components/error-notice';
import { LiveActivity } from './live-activity';
import { CountChart } from './count-chart';
@Component({
  imports: [InfoPopup,FormsModule, RouterLink, DatePipe, DecimalPipe, ErrorNotice, CountChart, LiveActivity],
  template: `
    <div class="page-heading dashboard-heading">
      <div>
        <p class="eyebrow">SECURITY OPERATIONS</p>
        <h1>Dashboard<span class="heading-dot">.</span></h1>
        <p class="muted">
          Your workspace at a glance. Every signal, every response, one clear picture.
        </p>
      </div>
      <a class="button" routerLink="/incidents/new">New incident</a>
    </div>
    <app-live-activity />
    <section class="overview-hero">
      <div>
        <p class="eyebrow">YOUR SECURITY WORKSPACE</p>
        <h2>Welcome back, {{ auth.user()?.fullName?.split(' ')?.[0] || 'analyst' }}.</h2>
        <p>Move from incoming signals to a coordinated response.</p>
        <div class="button-row">
          <a class="button hero-button" routerLink="/alerts">Triage alerts &rarr;</a
          ><a class="hero-link" routerLink="/iocs">Explore intelligence</a>
        </div>
      </div>
      <div class="hero-orbit" aria-hidden="true">
        <span class="orbit outer"></span><span class="orbit inner"></span
        ><span class="orbit-core">SOC</span><span class="orbit-point p1"></span
        ><span class="orbit-point p2"></span><span class="orbit-point p3"></span>
      </div>
    </section>
    <div class="dashboard-controls">
      <div>
        <label for="dashboard-period">Trend &amp; metrics period</label
        ><select
          id="dashboard-period"
          [ngModel]="period.value"
          (ngModelChange)="period.next(+$event)"
        >
          <option [ngValue]="7">Last 7 days</option>
          <option [ngValue]="30">Last 30 days</option>
          <option [ngValue]="90">Last 90 days</option>
        </select>
      </div>
      <div>
        <label for="dashboard-interval">Trend interval</label
        ><select
          id="dashboard-interval"
          [ngModel]="interval.value"
          (ngModelChange)="interval.next($event)"
        >
          <option value="day">Daily</option>
          <option value="week">Weekly</option>
        </select>
      </div>
      <button class="button secondary" [disabled]="state().loading" (click)="refresh.next()">
        Refresh dashboard
      </button>
    </div>
    <app-error-notice [messages]="state().errors" />
    @if (state().errors.length) {
      <button class="button secondary" (click)="refresh.next()">Try again</button>
    }
    @if (state().loading) {
      <div class="empty-state" role="status">Loading dashboard...</div>
    }
    @if (state().data; as data) {
      <p class="muted small-text">
        Incident totals refresh every 15 seconds while this tab is visible. The period selector applies to the trend and response metrics.
      </p>
      <div class="stat-grid spotlight-stats">
        <article class="stat-card">
          <span>Total incidents</span><strong>{{ data.summary.totalIncidents | number }}</strong
          ><a routerLink="/incidents">Open incident register &rarr;</a>
        </article>
        <article class="stat-card">
          <span>Open incidents</span><strong>{{ data.summary.openIncidents | number }}</strong
          ><small>Excludes resolved, closed, and false positives</small>
        </article>
        <article class="stat-card critical">
          <span>Critical &amp; open</span
          ><strong>{{ data.summary.criticalOpenIncidents | number }}</strong
          ><small>Highest severity in the open queue</small>
        </article>
        <article class="stat-card">
          <span>My open incidents</span><strong>{{ data.summary.myOpenIncidents | number }}</strong
          ><small>Currently assigned to you</small>
        </article>
      </div>
      <div class="mini-stats">
        <span
          >Unassigned open <strong>{{ data.summary.unassignedIncidents }}</strong></span
        ><a routerLink="/alerts"
          >New alerts <strong>{{ data.summary.newAlerts }}</strong></a
        ><span
          >Created today (UTC) <strong>{{ data.summary.incidentsCreatedToday }}</strong></span
        >
      </div>
      <section class="panel panel-padding">
        <div class="action-toolbar">
          <div>
            <h2>Incidents over time</h2>
            <p class="muted small-text">
              {{
                interval.value === 'week'
                  ? 'Seven-day buckets from the selected range start; the last may be partial.'
                  : 'Incidents created each day, including today.'
              }}
              Dates use UTC.
            </p>
          </div>
        </div>
        @if (!data.timeline.length) {
          <p class="muted">No time series available.</p>
        } @else {
          <svg
            class="trend-line-chart incident-trend"
            viewBox="0 0 800 240"
            role="img"
            [attr.aria-label]="
              'Incidents created over the last ' +
              period.value +
              ' days. Full values are in the data table below.'
            "
          >
            @for (fraction of [0, 0.5, 1]; track fraction) {
              <line
                x1="48"
                x2="780"
                [attr.y1]="210 - fraction * 180"
                [attr.y2]="210 - fraction * 180"
                class="trend-gridline"
              />
              <text x="38" [attr.y]="215 - fraction * 180" text-anchor="end" class="trend-tick">
                {{ maximum(data.timeline) * fraction | number: '1.0-1' }}
              </text>
            }
            <polyline [attr.points]="linePoints(data.timeline)" class="trend-series" />
            @for (row of data.timeline; track row.start; let index = $index) {
              <circle
                [attr.cx]="pointX(index, data.timeline.length)"
                [attr.cy]="210 - (row.count / maximum(data.timeline)) * 180"
                r="3.5"
                class="trend-point"
              >
                <title>{{ row.start | date: 'MMM d, y' : 'UTC' }}: {{ row.count }} incidents</title>
              </circle>
            }
          </svg>
          <div class="trend-axis">
            <span>{{ data.timeline[0].start | date: 'MMM d' : 'UTC' }}</span
            ><span>{{
              data.timeline[data.timeline.length - 1].start | date: 'MMM d' : 'UTC'
            }}</span>
          </div>
          <app-info-popup title="View trend data"><span popupTrigger>View trend data</span>
            <div class="table-scroll">
              <table>
                <caption class="sr-only">
                  Incident creation counts by UTC bucket start
                </caption>
                <thead>
                  <tr>
                    <th>Bucket start (UTC)</th>
                    <th>Incidents</th>
                  </tr>
                </thead>
                <tbody>
                  @for (row of data.timeline; track row.start) {
                    <tr>
                      <td>{{ row.start | date: 'mediumDate' : 'UTC' }}</td>
                      <td>{{ row.count }}</td>
                    </tr>
                  }
                </tbody>
              </table>
            </div>
          </app-info-popup>
        }
      </section>
      <div class="section-heading">
        <div>
          <p class="eyebrow">RESPONSE PERFORMANCE</p>
          <h2>Response metrics</h2>
        </div>
        <span class="badge neutral">Minutes &middot; measured from evidence</span>
      </div>
      <p class="muted small-text">
        Incidents created in the last {{ data.metrics.periodDays }} days. Unknown or invalid
        timestamps are excluded separately for each metric.
      </p>
      <div class="metrics-grid">
        @for (metric of metricRows(data.metrics); track metric.label) {
          <article class="stat-card">
            <span>{{ metric.label }}</span
            ><strong>{{
              metric.value === null ? 'No data' : (metric.value | number: '1.0-1') + ' min'
            }}</strong
            ><small>{{ metric.definition }}</small
            ><small
              >{{ metric.samples }} contributing
              {{ metric.samples === 1 ? 'incident' : 'incidents' }}</small
            >
            @if (metric.samples > 0 && metric.samples < 5) {
              <small class="sample-caution"
                >Small sample (fewer than 5 incidents). Interpret cautiously.</small
              >
            }
          </article>
        }
      </div>
      <p class="muted small-text">
        {{ data.metrics.sampleSize }} incidents in the selected period.
      </p>
      <div class="dashboard-grid">
        <app-count-chart title="Incidents by severity" [rows]="data.severity" /><app-count-chart
          title="Incidents by status"
          [rows]="data.status"
        /><app-count-chart title="Incidents by category" [rows]="data.category" /><app-count-chart
          title="Top IOC types"
          [rows]="data.iocTypes"
        />
      </div>
      <section class="panel panel-padding">
        <h2>Top MITRE techniques</h2>
        <p class="muted small-text">Ranked by linked incidents across the workspace.</p>
        @if (!data.techniques.length) {
          <p class="chart-empty muted">No linked techniques yet.</p>
        } @else {
          <div class="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>Technique</th>
                  <th>Name</th>
                  <th>Linked incidents</th>
                </tr>
              </thead>
              <tbody>
                @for (technique of data.techniques; track technique.techniqueId) {
                  <tr>
                    <td>
                      <code>{{ technique.techniqueId }}</code>
                    </td>
                    <td>{{ technique.name }}</td>
                    <td>{{ technique.count }}</td>
                  </tr>
                }
              </tbody>
            </table>
          </div>
        }
      </section>
    }
  `,
})
export class Dashboard {
  protected readonly auth = inject(Auth);
  private readonly api = inject(DashboardApi);
  protected readonly period = new BehaviorSubject(30);
  protected readonly interval = new BehaviorSubject('day');
  protected readonly refresh = new Subject<void>();
  protected readonly state = toSignal(
    combineLatest([this.period, this.interval, merge(this.refresh, timer(0, 15000).pipe(filter(() => !document.hidden)))]).pipe(
      switchMap(([days, interval]) =>
        this.api.load(days, interval).pipe(
          map((data) => ({ loading: false, data, errors: [] as string[] })),
          catchError((e) => of({ loading: false, data: null, errors: apiErrors(e) })),

        ),
      ),
      scan((previous, current) => ({ ...current, data: current.data ?? previous.data })),
    ),
    { initialValue: { loading: true, data: null, errors: [] as string[] } },
  );
  protected maximum(rows: TimeBucket[]): number {
    return Math.max(1, ...rows.map((row) => row.count));
  }
  protected pointX(index: number, length: number): number {
    return length === 1 ? 414 : 48 + (index / (length - 1)) * 732;
  }
  protected linePoints(rows: TimeBucket[]): string {
    const max = this.maximum(rows);
    return rows
      .map((row, index) => `${this.pointX(index, rows.length)},${210 - (row.count / max) * 180}`)
      .join(' ');
  }
  protected metricRows(metrics: DashboardMetrics) {
    return [
      {
        label: 'Mean time to detect',
        value: metrics.meanTimeToDetectMinutes,
        samples: metrics.detectionSampleSize,
        definition: 'Occurrence to detection',
      },
      {
        label: 'Mean time to contain',
        value: metrics.meanTimeToContainMinutes,
        samples: metrics.containmentSampleSize,
        definition: 'Detection to containment',
      },
      {
        label: 'Mean time to resolve',
        value: metrics.meanTimeToResolveMinutes,
        samples: metrics.resolutionSampleSize,
        definition: 'Detection to resolution',
      },
    ];
  }
}
