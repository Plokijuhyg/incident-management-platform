import { InfoPopup } from '../../shared/components/detail-modal';
import { DetailModal } from '../../shared/components/detail-modal';
import { Component, DestroyRef, inject, signal } from '@angular/core';
import { HttpClient, HttpParams } from '@angular/common/http';
import { DatePipe, DecimalPipe } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { finalize, forkJoin, Subscription, timer } from 'rxjs';
import { ErrorNotice } from '../../shared/components/error-notice';
import { apiErrors } from '../../core/services/api-errors';
import { utcTimestamp } from '../../core/services/incidents';
interface EventRow {
  id: number;
  machine: string;
  channel: string;
  provider: string;
  recordId: number | null;
  eventId: number;
  level: number;
  timeCreated: string | null;
  receivedAt: string;
  alertId: number | null;
  message?: string;
  rawXml?: string;
}
interface Channel {
  id: number;
  machine: string;
  channel: string;
  enabled: boolean;
  startedAt: string;
  lastCheckedAt: string | null;
  lastEventAt: string | null;
  error: string | null;
  hasBacklog: boolean;
}
interface Status {
  enabled: boolean;
  pollSeconds: number;
  retentionDays: number;
  lastCycleAt: string | null;
  error: string | null;
  machine: string;
  windowsSupported: boolean;
  storedEvents: number;
  channels: Channel[];
}
@Component({
  imports: [InfoPopup,DetailModal,FormsModule, DatePipe, DecimalPipe, RouterLink, ErrorNotice],
  template: `<div class="page-heading">
      <div>
        <p class="eyebrow">HOST TELEMETRY</p>
        <h1>Windows Events</h1>
        <p class="muted">Original events collected from Windows on the API host.</p>
      </div>
      <button class="button secondary" (click)="toggle()">
        {{ live() ? 'Pause live view' : 'Resume live view' }}
      </button>
    </div>
    <app-error-notice [messages]="errors()" />
    @if (status(); as s) {
      <div class="stat-grid">
        <article class="stat-card">
          <span>Stored events</span><strong>{{ s.storedEvents | number }}</strong
          ><small>Rolling {{ s.retentionDays }}-day retention</small>
        </article>
        <article class="stat-card">
          <span>Host</span><strong class="host-name">{{ s.machine }}</strong
          ><small>{{ s.enabled ? 'Collector enabled' : 'Collector disabled' }}</small>
        </article>
        <article class="stat-card">
          <span>Channel coverage</span><strong>{{ readable(s) }} / {{ enabled(s) }}</strong
          ><small>Enabled channels read successfully</small>
        </article>
        <article class="stat-card">
          <span>Live view</span><strong>{{ live() ? 'Refreshing' : 'Paused' }}</strong
          ><small>Latest successful API refresh: {{ refreshedAt() | date: 'mediumTime' }}</small>
        </article>
      </div>
      @if (!s.enabled) {
        <p class="notice">
          Collection is disabled. Set WindowsEvents:Enabled to true on the API host and restart it.
        </p>
      }
      @if (s.error) {
        <p class="error-notice" role="alert">{{ s.error }}</p>
      }
      <p class="muted small-text">
        Collector checks channels every {{ s.pollSeconds }} seconds after each sweep; this page
        refreshes every 3 seconds. Busy channels may need time to catch up. Last completed sweep:
        {{ date(s.lastCycleAt) }}.
      </p>
      <app-info-popup title="Channel coverage and collection errors"><span popupTrigger>Channel coverage and collection errors</span>
        <p class="muted">
          All enabled Windows Event Log channels are attempted. Disabled, inaccessible or
          stale-bookmark channels are listed explicitly. This does not include arbitrary application
          text files, disabled audit events or logs that Windows already overwrote.
        </p>
        <div class="table-scroll channel-coverage">
          <table>
            <thead>
              <tr>
                <th>Channel</th>
                <th>Status</th>
                <th>Collecting since</th>
                <th>Last check</th>
              </tr>
            </thead>
            <tbody>
              @for (c of s.channels; track c.id) {
                <tr>
                  <td>{{ c.channel }}</td>
                  <td>
                    {{
                      c.error ||
                        (c.hasBacklog ? 'Catching up' : c.lastCheckedAt ? 'Reading' : 'Waiting')
                    }}
                  </td>
                  <td>{{ date(c.startedAt) }}</td>
                  <td>{{ date(c.lastCheckedAt) }}</td>
                </tr>
              }
            </tbody>
          </table>
        </div>
      </app-info-popup>
    }
    <section class="panel">
      <form class="filter-bar" (ngSubmit)="apply()">
        <div>
          <label for="event-channel">Channel</label
          ><select id="event-channel" name="channel" [(ngModel)]="channel">
            <option value="">All channels</option>
            @for (c of status()?.channels; track c.id) {
              @if (c.enabled) {
                <option [value]="c.channel">{{ c.channel }}</option>
              }
            }
          </select>
        </div>
        <div>
          <label for="event-id">Event ID</label
          ><input id="event-id" name="eventId" type="number" min="0" [(ngModel)]="eventId" />
        </div>
        <div>
          <label for="event-level">Windows level</label
          ><select id="event-level" name="level" [(ngModel)]="level">
            <option value="">All levels</option>
            @for (label of levels; track $index) {
              <option [value]="$index">{{ label }}</option>
            }
          </select>
        </div>
        <div>
          <label for="event-search">Provider, message or host</label
          ><input id="event-search" name="search" maxlength="200" [(ngModel)]="search" />
        </div>
        <button class="button" [disabled]="busy()">Apply filters</button>
      </form>
      <p class="panel-padding muted small-text">
        Windows level describes the event; it is not vulnerability severity. Only matching detection
        rules create alerts. Incidents require analyst review.
      </p>
      @if (busy() && !rows().length) {
        <p class="empty-state" role="status">Loading events...</p>
      } @else if (!rows().length) {
        <div class="empty-state">
          <h2>No matching events yet</h2>
          <p>
            Check collector status and channel permissions above. No demonstration data is shown.
          </p>
        </div>
      } @else {
        <div class="table-scroll">
          <table>
            <thead>
              <tr>
                <th>Time</th>
                <th>Channel / provider</th>
                <th>Event ID</th>
                <th>Level</th>
                <th>Evidence</th>
              </tr>
            </thead>
            <tbody>
              @for (row of rows(); track row.id) {
                <tr>
                  <td>{{ date(row.timeCreated) }}</td>
                  <td>
                    <strong>{{ row.channel }}</strong
                    ><br /><small>{{ row.provider }}</small>
                  </td>
                  <td>{{ row.eventId }}</td>
                  <td>
                    <span class="badge neutral">{{ levels[row.level] || 'Unknown' }}</span>
                  </td>
                  <td>
                    <button class="link-button" (click)="open(row.id)">Inspect event</button>
                    @if (row.alertId) {
                      <br /><a [routerLink]="['/alerts', row.alertId]">Review alert &rarr;</a>
                    }
                  </td>
                </tr>
              }
            </tbody>
          </table>
        </div>
      }
      <footer class="pagination">
        <span
          >{{ rows().length }} events shown
          {{ before ? '(historical page)' : '(latest page)' }}</span
        >
        <div>
          <button class="button secondary small" (click)="latest()" [disabled]="busy()">
            Latest</button
          ><button
            class="button secondary small"
            (click)="older()"
            [disabled]="!hasMore() || busy()"
          >
            Older events
          </button>
        </div>
      </footer>
    </section>
    @if (selected(); as e) {
      <app-detail-modal title="Windows event details" (closed)="selected.set(null)"><section class="event-detail" aria-label="Original Windows event">
        <div class="action-toolbar">
          <h2>Event {{ e.eventId }} &middot; Record {{ e.recordId }}</h2>
          
        </div>
        <p>{{ e.machine }} &middot; {{ e.channel }} &middot; {{ date(e.timeCreated) }}</p>
        <h3>Rendered message</h3>
        <pre class="raw-output">{{ e.message }}</pre>
        <app-info-popup title="Original Windows XML"><span popupTrigger>Original Windows XML</span>
          <pre class="raw-output">{{ e.rawXml }}</pre>
        </app-info-popup>
      </section></app-detail-modal>
    } `,
})
export class WindowsEventsPage {
  private http = inject(HttpClient);
  private destroy = inject(DestroyRef);
  private detailRequest?: Subscription;
  protected status = signal<Status | null>(null);
  protected rows = signal<EventRow[]>([]);
  protected selected = signal<EventRow | null>(null);
  protected errors = signal<string[]>([]);
  protected busy = signal(false);
  protected live = signal(true);
  protected hasMore = signal(false);
  protected refreshedAt = signal<Date | null>(null);
  protected channel = '';
  protected eventId: number | null = null;
  protected level = '';
  protected search = '';
  protected before: number | null = null;
  private applied = { channel: '', eventId: null as number | null, level: '', search: '' };
  protected levels = ['Log always', 'Critical', 'Error', 'Warning', 'Information', 'Verbose'];
  constructor() {
    timer(0, 3000)
      .pipe(takeUntilDestroyed())
      .subscribe(() => {
        if (this.live() && !document.hidden) this.load();
      });
  }
  protected date(value: string | null) {
    return value ? new Date(utcTimestamp(value)).toLocaleString() : 'Not recorded';
  }
  protected enabled(s: Status) {
    return s.channels.filter((c) => c.enabled).length;
  }
  protected readable(s: Status) {
    return s.channels.filter((c) => c.enabled && c.lastCheckedAt && !c.error).length;
  }
  protected toggle() {
    this.live.update((v) => !v);
    if (this.live()) this.latest();
  }
  protected apply() {
    this.applied = {
      channel: this.channel,
      eventId: this.eventId,
      level: this.level,
      search: this.search,
    };
    this.before = null;
    this.load();
  }
  protected latest() {
    this.before = null;
    this.load();
  }
  protected older() {
    if (!this.rows().length) return;
    this.live.set(false);
    this.before = this.rows().at(-1)!.id;
    this.load();
  }
  private load() {
    if (this.busy()) return;
    this.busy.set(true);
    let params = new HttpParams().set('limit', 100);
    for (const [k, v] of Object.entries(this.applied))
      if (v !== null && v !== '') params = params.set(k, v);
    if (this.before) params = params.set('before', this.before);
    forkJoin({
      status: this.http.get<Status>('/api/windows-events/status'),
      events: this.http.get<{ items: EventRow[]; hasMore: boolean }>('/api/windows-events', {
        params,
      }),
    })
      .pipe(
        takeUntilDestroyed(this.destroy),
        finalize(() => this.busy.set(false)),
      )
      .subscribe({
        next: (r) => {
          this.status.set(r.status);
          this.rows.set(r.events.items);
          this.hasMore.set(r.events.hasMore);
          this.errors.set([]);
          this.refreshedAt.set(new Date());
        },
        error: (e) => {
          this.errors.set(apiErrors(e));
        },
      });
  }
  protected open(id: number) {
    this.detailRequest?.unsubscribe();
    this.detailRequest = this.http
      .get<EventRow>('/api/windows-events/' + id)
      .pipe(takeUntilDestroyed(this.destroy))
      .subscribe({
        next: (e) => {
          this.selected.set(e);
        },
        error: (e) => this.errors.set(apiErrors(e)),
      });
  }
}
