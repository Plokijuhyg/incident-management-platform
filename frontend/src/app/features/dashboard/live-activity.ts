import { InfoPopup } from '../../shared/components/detail-modal';
import { DatePipe, DecimalPipe } from '@angular/common';
import { HttpClient } from '@angular/common/http';
import { Component, inject, signal } from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { RouterLink } from '@angular/router';
import { EMPTY, catchError, exhaustMap, filter, timer } from 'rxjs';
import { Auth } from '../../core/services/auth';
import { Incidents, utcTimestamp } from '../../core/services/incidents';
import { IncidentSummary, statuses } from '../../core/models/api';
import { TimeBucket } from '../../core/models/operations';
import { SeverityBadge } from '../../shared/components/severity-badge';
import { CountChart } from './count-chart';

interface Activity {
  observedAt: string; enabled: boolean; windowsSupported: boolean; error: string | null;
  lastCycleAt: string | null; lastReceivedAt: string | null; retentionDays: number;
  storedEvents: number; eventsLastMinute: number; enabledChannels: number;
  readableChannels: number; blockedChannels: number; backlogChannels: number;
  timeline: TimeBucket[]; topChannels: { label: string; count: number }[];
  latest: { id: number; channel: string; provider: string; eventId: number;
    level: number; receivedAt: string; timeCreated: string | null; alertId: number | null }[];
}
@Component({
  selector: 'app-live-activity',
  imports: [InfoPopup,DatePipe, DecimalPipe, RouterLink, SeverityBadge, CountChart],
  styles: [`:host { display:block; margin-bottom:2rem; } .live-heading { display:flex; gap:1rem; justify-content:space-between; align-items:center; flex-wrap:wrap; } .health-note { padding:1rem; border-left:3px solid #d99a26; background:#fff8e8; color:#68480f; } .feed-grid { display:grid; grid-template-columns:minmax(0,2fr) minmax(0,1fr); gap:1.25rem; margin:1.25rem 0; } .live-dot { display:inline-block; width:.5rem; height:.5rem; border-radius:50%; background:#008b8b; margin-right:.5rem; } @media(max-width:1000px) { .feed-grid {grid-template-columns:1fr;} }`],
  template: `
    <div class="live-heading section-heading">
      <div><p class="eyebrow">LIVE OPERATIONS</p><h2>Incoming activity</h2></div>
      <button class="button secondary" (click)="paused.set(!paused())">{{ paused() ? 'Resume activity' : 'Pause activity' }}</button>
    </div>
    <p class="muted small-text"><span class="live-dot" aria-hidden="true"></span>{{ paused() ? 'Activity paused.' : 'Events refresh every 5 seconds; incidents every 15 seconds while this tab is visible.' }} Collection continues on the backend.</p>
    @if (auth.canManageIncidents()) {
      @if (eventError()) { <p class="health-note" role="alert">{{ eventError() }} Previously loaded data may be stale.</p> }
      @if (activity(); as data) {
        <p class="muted small-text">Last successful refresh: {{ utc(data.observedAt) | date:'mediumTime' }}. Last event received: {{ data.lastReceivedAt ? (utc(data.lastReceivedAt) | date:'medium') : 'None yet' }}.</p>
        @if (!data.enabled || !data.windowsSupported || data.error || stale(data.lastCycleAt) || data.blockedChannels || data.backlogChannels) {
          <div class="health-note">
            @if (!data.enabled) { <p>Windows collection is disabled. Enable WindowsEvents:Enabled on the API host.</p> }
            @if (!data.windowsSupported) { <p>The local collector requires a Windows API host.</p> }
            @if (data.error) { <p>{{ data.error }}</p> }
            @if (data.enabled && stale(data.lastCycleAt)) { <p>No completed collection sweep in the last 2 minutes. Collection may be catching up; inspect channel status.</p> }
            @if (data.blockedChannels) { <p>{{ data.blockedChannels }} enabled channels could not be read. Protected channels such as Security need Windows Event Log permissions.</p> }
            @if (data.backlogChannels) { <p>{{ data.backlogChannels }} channels have a collection backlog.</p> }
            <a routerLink="/windows-events">Inspect collection status and channel errors &rarr;</a>
          </div>
        }
        <div class="stat-grid spotlight-stats section-space">
          <article class="stat-card"><span>Stored Windows events</span><strong>{{ data.storedEvents | number }}</strong><small>{{ data.retentionDays }}-day retention</small></article>
          <article class="stat-card"><span>Events received / last 60s</span><strong>{{ data.eventsLastMinute | number }}</strong><small>Actual ingestion volume</small></article>
          <article class="stat-card"><span>Average events / second</span><strong>{{ data.eventsLastMinute / 60 | number:'1.0-2' }}</strong><small>Measured over the last 60 seconds</small></article>
          <article class="stat-card"><span>Readable channels</span><strong>{{ data.readableChannels }} / {{ data.enabledChannels }}</strong><a routerLink="/windows-events">View Windows events &rarr;</a></article>
        </div>
        <div class="feed-grid">
          <section class="panel panel-padding">
            <h3>Log ingestion over time</h3><p class="muted small-text">Received events per minute, last 30 minutes. Current minute is partial. These are logs, not incident counts.</p>
            <svg class="trend-line-chart" viewBox="0 0 800 240" role="img" aria-label="Received Windows events per minute over the last 30 minutes">
              @for (fraction of [0, 0.5, 1]; track fraction) {
                <line x1="48" x2="780" [attr.y1]="210-fraction*180" [attr.y2]="210-fraction*180" class="trend-gridline" />
                <text x="38" [attr.y]="215-fraction*180" text-anchor="end" class="trend-tick">{{ maximum(data.timeline)*fraction | number:'1.0-0' }}</text>
              }
              <polyline [attr.points]="points(data.timeline)" class="trend-series" />
              @for (row of data.timeline; track row.start; let i = $index) {
                <circle [attr.cx]="48+i/29*732" [attr.cy]="210-row.count/maximum(data.timeline)*180" r="3" class="trend-point"><title>{{ utc(row.start) | date:'HH:mm' }}: {{ row.count }} events</title></circle>
              }
            </svg>
            <div class="trend-axis"><span>{{ utc(data.timeline[0].start) | date:'HH:mm' }}</span><span>{{ utc(data.timeline[29].start) | date:'HH:mm' }}</span></div>
            <app-info-popup title="View ingestion counts"><span popupTrigger>View ingestion counts</span><div class="table-scroll"><table><thead><tr><th>Minute</th><th>Events</th></tr></thead><tbody>@for (row of data.timeline; track row.start) {<tr><td>{{ utc(row.start) | date:'HH:mm' }}</td><td>{{ row.count }}</td></tr>}</tbody></table></div></app-info-popup>
          </section>
          <app-count-chart title="Top channels / last 30 minutes" [rows]="data.topChannels" />
        </div>
        <section class="panel panel-padding">
          <div class="live-heading"><h3>Latest Windows events</h3><a routerLink="/windows-events">Search all collected logs &rarr;</a></div>
          <div class="table-scroll"><table><thead><tr><th>Received</th><th>Channel / provider</th><th>Event ID</th><th>Windows level</th><th>Detection</th></tr></thead><tbody>
            @for (row of data.latest; track row.id) {
              <tr><td>{{ utc(row.receivedAt) | date:'mediumTime' }}</td><td>{{ row.channel }}<br><small class="muted">{{ row.provider }}</small></td><td>{{ row.eventId }}</td><td>{{ levels.at(row.level) ?? 'Unknown' }}</td><td>@if (row.alertId) {<a routerLink="/alerts">Alert #{{ row.alertId }}</a>} @else {<span class="muted">No rule match</span>}</td></tr>
            } @empty { <tr><td colspan="5">No events collected yet. Check collection status above.</td></tr> }
          </tbody></table></div>
        </section>
      } @else if (!eventError()) { <p role="status">Loading live Windows activity...</p> }
    } @else { <p class="muted">Raw Windows telemetry is available to administrators and security managers. Your incident dashboard updates below.</p> }
    <section class="panel panel-padding section-space">
      <div class="live-heading"><h3>Latest incidents</h3><a routerLink="/incidents">All incidents &rarr;</a></div>
      <p class="muted small-text">Latest 10 created incidents across all statuses. Logs matching detection rules create alerts; review an alert and promote it to an incident when investigation is needed.</p>
      @if (incidentError()) { <p class="health-note" role="alert">{{ incidentError() }} Previously loaded incidents may be stale.</p> }
      <div class="table-scroll"><table><thead><tr><th>Incident</th><th>Title</th><th>Severity</th><th>Status</th><th>Created</th></tr></thead><tbody>
        @for (row of incidents(); track row.id) { <tr><td><a [routerLink]="['/incidents',row.id]">{{ row.incidentNumber }}</a></td><td>{{ row.title }}</td><td><app-severity [value]="row.severity" /></td><td>{{ statuses[row.status] }}</td><td>{{ row.createdAt | date:'short' }}</td></tr> }
        @empty { <tr><td colspan="5">{{ incidentsLoaded() ? 'No incidents recorded. Incoming logs appear above; alerts require triage.' : 'Loading incidents...' }}</td></tr> }
      </tbody></table></div>
    </section>
  `,
})
export class LiveActivity {
  protected readonly auth = inject(Auth);
  private readonly http = inject(HttpClient);
  private readonly api = inject(Incidents);
  protected readonly activity = signal<Activity | null>(null);
  protected readonly incidents = signal<IncidentSummary[]>([]);
  protected readonly incidentsLoaded = signal(false);
  protected readonly eventError = signal('');
  protected readonly incidentError = signal('');
  protected readonly paused = signal(false);
  protected readonly statuses = statuses;
  protected readonly levels = ['Log always', 'Critical', 'Error', 'Warning', 'Information', 'Verbose'];
  protected readonly utc = utcTimestamp;
  constructor() {
    timer(0, 5000).pipe(
      filter(() => this.auth.canManageIncidents() && !this.paused() && !document.hidden),
      exhaustMap(() => this.http.get<Activity>('/api/windows-events/activity').pipe(catchError(() => {
        this.eventError.set('Unable to refresh Windows activity. Check the API connection.'); return EMPTY;
      }))), takeUntilDestroyed(),
    ).subscribe(data => { this.activity.set(data); this.eventError.set(''); });
    timer(0, 15000).pipe(
      filter(() => !this.paused() && !document.hidden),
      exhaustMap(() => this.api.list(1, 10).pipe(catchError(() => {
        this.incidentError.set('Unable to refresh incidents.'); return EMPTY;
      }))), takeUntilDestroyed(),
    ).subscribe(data => { this.incidents.set(data.items); this.incidentsLoaded.set(true); this.incidentError.set(''); });
  }
  protected stale(value: string | null): boolean { return !value || Date.now() - Date.parse(utcTimestamp(value)) > 120000; }
  protected maximum(rows: TimeBucket[]): number { return Math.max(1, ...rows.map(row => row.count)); }
  protected points(rows: TimeBucket[]): string { const max=this.maximum(rows); return rows.map((row,i) => `${48+i/29*732},${210-row.count/max*180}`).join(' '); }
}
