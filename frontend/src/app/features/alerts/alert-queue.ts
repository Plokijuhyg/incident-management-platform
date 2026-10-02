import { DatePipe } from '@angular/common';
import { Component, DestroyRef, computed, effect, inject, signal } from '@angular/core';
import { takeUntilDestroyed, toSignal } from '@angular/core/rxjs-interop';
import { FormsModule } from '@angular/forms';
import { ActivatedRoute, ParamMap, Router, RouterLink } from '@angular/router';
import { Observable, Subject, Subscription, filter, finalize, merge, switchMap, timer } from 'rxjs';
import {
  AlertDetail,
  AlertSummary,
  categories,
  priorities,
  severities,
} from '../../core/models/api';
import {
  alertSources,
  alertStatuses,
  catalogs,
  selectField,
  textField,
} from '../../core/models/catalog';
import { Alerts, incidentSeverityFor } from '../../core/services/alerts';
import { apiErrors } from '../../core/services/api-errors';
import { DataForm, Field } from '../../shared/components/data-form';
import { InfoPopup } from '../../shared/components/detail-modal';
import { ErrorNotice } from '../../shared/components/error-notice';
import { IntelPanel } from '../../shared/components/intel-panel';
import { SortHeader, SortState } from '../../shared/components/sort-header';

const OPEN_STATUSES = [0, 1];
const PENTEST_SOURCE = 6;
const sortKeys = ['detectedAt', 'severity', 'status', 'source', 'title'];
export const alertSeverityOptions = ['Critical', 'High', 'Medium', 'Low'];

export interface AlertFilters {
  search: string;
  status: string;
  source: string;
  severity: string;
  /** The working queue (New + In review) is the default view; `open=false` shows everything. */
  open: boolean;
  sort: string;
  dir: string;
}
/** Reads list state from the URL, discarding anything the API would reject. */
export function readAlertFilters(params: ParamMap): AlertFilters {
  const index = (value: string | null, max: number) =>
    value !== null && /^\d+$/.test(value) && Number(value) < max ? value : '';
  const sort = params.get('sort') ?? '';
  const severity = params.get('severity') ?? '';
  return {
    search: (params.get('search') ?? '').slice(0, 200),
    status: index(params.get('status'), alertStatuses.length),
    source: index(params.get('source'), alertSources.length),
    severity: alertSeverityOptions.includes(severity) ? severity : '',
    open: params.get('open') !== 'false',
    sort: sortKeys.includes(sort) ? sort : '',
    dir: params.get('dir') === 'asc' ? 'asc' : params.get('dir') === 'desc' ? 'desc' : '',
  };
}

function selectedAlertId(params: ParamMap): number | null {
  const id = Number(params.get('id'));
  return Number.isSafeInteger(id) && id > 0 ? id : null;
}

@Component({
  imports: [
    DatePipe,
    FormsModule,
    RouterLink,
    DataForm,
    ErrorNotice,
    InfoPopup,
    IntelPanel,
    SortHeader,
  ],
  template: `
    <div class="page-heading compact-heading">
      <div>
        <p class="eyebrow">DETECTION &amp; TRIAGE</p>
        <h1>Alerts</h1>
      </div>
      <button class="button" (click)="startCreate()">+ New alert</button>
    </div>
    <app-error-notice [messages]="errors()" />
    @if (message()) {
      <p class="success-notice" role="status">{{ message() }}</p>
    }
    <div class="triage-layout" [class.with-panel]="panelOpen()">
      <section class="panel triage-queue" aria-label="Alert queue">
        <form class="filter-bar" role="search" (ngSubmit)="apply({ search: searchText.trim() })">
          <div>
            <label for="alert-search">Search</label
            ><input
              id="alert-search"
              name="search"
              type="search"
              maxlength="200"
              [(ngModel)]="searchText"
              placeholder="Title, description or rule ID"
            />
          </div>
          <div>
            <label for="alert-severity">Severity</label
            ><select
              id="alert-severity"
              name="severity"
              [ngModel]="filters().severity"
              (ngModelChange)="apply({ severity: $event })"
            >
              <option value="">Any severity</option>
              @for (label of severityOptions; track label) {
                <option [value]="label">{{ label }}</option>
              }
            </select>
          </div>
          <div>
            <label for="alert-status">Status</label
            ><select
              id="alert-status"
              name="status"
              [ngModel]="filters().status"
              (ngModelChange)="apply({ status: $event })"
            >
              <option value="">Any status</option>
              @for (label of statusLabels; track $index) {
                <option [value]="'' + $index">{{ label }}</option>
              }
            </select>
          </div>
          <div>
            <label for="alert-source">Source</label
            ><select
              id="alert-source"
              name="source"
              [ngModel]="filters().source"
              (ngModelChange)="apply({ source: $event })"
            >
              <option value="">Any source</option>
              @for (label of sourceLabels; track $index) {
                <option [value]="'' + $index">{{ label }}</option>
              }
            </select>
          </div>
          <label class="inline-check"
            ><input
              type="checkbox"
              name="open"
              [ngModel]="filters().open"
              (ngModelChange)="apply({ open: $event ? null : 'false' })"
            />
            Open only</label
          >
          <button class="button secondary">Search</button>
          @if (filtered()) {
            <button type="button" class="link-button" (click)="clear()">Reset view</button>
          }
        </form>
        <p class="queue-status muted small-text" role="status">
          {{ loading() ? 'Loading alerts...' : total() + (total() === 1 ? ' alert' : ' alerts') }}
          @if (filters().open && !filters().status) {
            &middot; open queue (New and In review)
          }
          &middot; refreshes every 30 seconds
        </p>
        @if (rows().length) {
          <div class="table-scroll">
            <table class="queue-table">
              <caption class="sr-only">
                Alerts, page
                {{
                  page()
                }}
                of
                {{
                  pages() || 1
                }}
              </caption>
              <thead>
                <tr>
                  <th
                    sortKey="title"
                    firstDirection="asc"
                    [state]="sort()"
                    (sorted)="apply($event)"
                  >
                    Signal
                  </th>
                  <th sortKey="severity" [state]="sort()" (sorted)="apply($event)">Severity</th>
                  <th
                    sortKey="source"
                    firstDirection="asc"
                    [state]="sort()"
                    (sorted)="apply($event)"
                  >
                    Source
                  </th>
                  <th
                    sortKey="status"
                    firstDirection="asc"
                    [state]="sort()"
                    (sorted)="apply($event)"
                  >
                    Status
                  </th>
                  <th sortKey="detectedAt" [state]="sort()" (sorted)="apply($event)">
                    Detected (UTC)
                  </th>
                </tr>
              </thead>
              <tbody>
                @for (row of rows(); track row.id) {
                  <tr
                    [class.selected]="row.id === selectedId()"
                    [attr.aria-current]="row.id === selectedId() ? 'true' : null"
                  >
                    <td>
                      <a [routerLink]="['/alerts', row.id]" queryParamsHandling="preserve">{{
                        row.title
                      }}</a>
                      @if (row.sourceRuleId) {
                        <span class="rule-id">{{ row.sourceRuleId }}</span>
                      }
                    </td>
                    <td>
                      <span [class]="severityClass(row.severity)">{{
                        row.severity || 'Unknown'
                      }}</span>
                    </td>
                    <td>{{ sourceLabels.at(row.source) ?? 'Unknown' }}</td>
                    <td>
                      <span class="badge neutral">{{
                        statusLabels.at(row.status) ?? 'Unknown'
                      }}</span>
                    </td>
                    <td class="nowrap">{{ row.detectedAt | date: 'MMM d, y, HH:mm' : 'UTC' }}</td>
                  </tr>
                }
              </tbody>
            </table>
          </div>
        } @else if (!loading()) {
          <div class="empty-state">
            <h2>{{ filtered() ? 'No alerts match this view' : 'The open queue is empty' }}</h2>
            <p>
              {{
                filtered()
                  ? 'Try a broader search or reset the view.'
                  : 'New detections will appear here automatically.'
              }}
            </p>
            @if (filters().open) {
              <button class="button secondary" (click)="apply({ open: 'false' })">
                Show all alerts
              </button>
            } @else if (filtered()) {
              <button class="button secondary" (click)="clear()">Reset view</button>
            }
          </div>
        }
        <footer class="pagination">
          <span>Page {{ page() }} of {{ pages() || 1 }}</span>
          <div>
            <button
              class="button secondary small"
              [disabled]="page() <= 1 || loading()"
              (click)="go(page() - 1)"
            >
              &larr; Previous</button
            ><button
              class="button secondary small"
              [disabled]="page() >= pages() || loading()"
              (click)="go(page() + 1)"
            >
              Next &rarr;
            </button>
          </div>
        </footer>
      </section>

      @if (panelOpen()) {
        <section
          class="panel panel-padding triage-panel"
          aria-label="Alert triage"
          (keydown.escape)="closePanel()"
        >
          <button type="button" class="link-button panel-close" (click)="closePanel()">
            Close panel <span aria-hidden="true">&times;</span>
          </button>
          @if (creating()) {
            <h2>New alert</h2>
            <app-data-form
              [fields]="createFields"
              prefix="new-alert-"
              [busy]="busy()"
              label="Create alert"
              (saved)="create($event)"
            />
          } @else if (detailLoading()) {
            <div class="empty-state" role="status">Loading alert...</div>
          } @else if (detail(); as alert) {
            <p class="eyebrow">
              Alert #{{ alert.id }}
              @if (alert.sourceRuleId) {
                &middot; {{ alert.sourceRuleId }}
              }
            </p>
            <h2 class="break-word">{{ alert.title }}</h2>
            <dl class="triage-facts">
              <div>
                <dt>Severity</dt>
                <dd>
                  <span [class]="severityClass(alert.severity)">{{
                    alert.severity || 'Unknown'
                  }}</span>
                </dd>
              </div>
              <div>
                <dt>Status</dt>
                <dd>
                  <span class="badge neutral">{{
                    statusLabels.at(alert.status) ?? 'Unknown'
                  }}</span>
                </dd>
              </div>
              <div>
                <dt>Source</dt>
                <dd>{{ sourceLabels.at(alert.source) ?? 'Unknown' }}</dd>
              </div>
              <div>
                <dt>Detected (UTC)</dt>
                <dd>{{ alert.detectedAt | date: 'MMM d, y, HH:mm:ss' : 'UTC' }}</dd>
              </div>
              <div>
                <dt>Received (UTC)</dt>
                <dd>
                  {{ (alert.receivedAt | date: 'MMM d, y, HH:mm:ss' : 'UTC') || 'Not recorded' }}
                </dd>
              </div>
            </dl>
            @if (alert.recommendedAction) {
              <h3>Recommended response</h3>
              <p class="notice">
                Suggestion only. Human review is required; no action has been executed.
              </p>
              <p>{{ alert.recommendedAction }}</p>
            }
            <p class="description">{{ alert.description || 'No description provided.' }}</p>
            @if (alert.rawPayload) {
              <app-info-popup title="Original evidence / tool output"
                ><span popupTrigger>Original evidence / tool output</span>
                <pre class="raw-output">{{ alert.rawPayload }}</pre>
              </app-info-popup>
            }
            @if (alert.source === pentestSource) {
              <p class="notice">
                PenTest signal. Original payload is tool evidence; descriptions may contain analyst
                or AI interpretation. Validate evidence before promotion.
              </p>
            }
            @if (alert.incidentId) {
              <a class="button secondary" [routerLink]="['/incidents', alert.incidentId]"
                >Open linked incident &rarr;</a
              >
            }
            @if (isOpen(alert)) {
              <hr />
              <h3>Promote to incident</h3>
              <p class="muted small-text">
                Severity and priority start from the source severity; adjust after reviewing the
                evidence.
              </p>
              <app-data-form
                [fields]="promoteFields"
                [value]="promotion()"
                prefix="promote-"
                [busy]="busy()"
                label="Promote to incident"
                (saved)="promote(alert, $event)"
              />
              <hr />
              <h3>Mark false positive</h3>
              <app-data-form
                [fields]="reasonFields"
                prefix="false-positive-"
                [busy]="busy()"
                label="Confirm false positive"
                (saved)="falsePositive(alert, $event)"
              />
            }
            <hr />
            <app-intel-panel kind="alerts" [recordId]="alert.id" />
          }
        </section>
      }
    </div>
  `,
})
export class AlertQueue {
  private readonly route = inject(ActivatedRoute);
  private readonly router = inject(Router);
  private readonly alerts = inject(Alerts);
  private readonly destroy = inject(DestroyRef);
  protected readonly severityOptions = alertSeverityOptions;
  protected readonly statusLabels = alertStatuses;
  protected readonly sourceLabels = alertSources;
  protected readonly pentestSource = PENTEST_SOURCE;
  protected readonly createFields = catalogs['alerts'].fields;
  protected readonly reasonFields: Field[] = [
    { key: 'reason', label: 'Reason', type: 'textarea', required: true },
  ];
  protected readonly promoteFields: Field[] = [
    textField('title', 'Incident title', true),
    selectField('severity', 'Severity', severities, 1),
    selectField('priority', 'Priority', priorities, 1),
    selectField('category', 'Category', categories, 9),
  ];

  private readonly params = toSignal(this.route.queryParamMap, {
    initialValue: this.route.snapshot.queryParamMap,
  });
  private readonly routeParams = toSignal(this.route.paramMap, {
    initialValue: this.route.snapshot.paramMap,
  });
  protected readonly filters = computed(() => readAlertFilters(this.params()));
  protected readonly sort = computed<SortState>(() => ({
    sort: this.filters().sort || 'detectedAt',
    direction: this.filters().dir === 'asc' ? 'asc' : 'desc',
  }));
  protected readonly filtered = computed(() => {
    const f = this.filters();
    return !!(f.search || f.status || f.source || f.severity || !f.open);
  });
  protected readonly selectedId = computed(() => selectedAlertId(this.routeParams()));
  protected readonly rows = signal<AlertSummary[]>([]);
  protected readonly page = signal(1);
  protected readonly pages = signal(1);
  protected readonly total = signal(0);
  protected readonly loading = signal(true);
  protected readonly detail = signal<AlertDetail | null>(null);
  protected readonly detailLoading = signal(false);
  protected readonly creating = signal(false);
  protected readonly busy = signal(false);
  protected readonly errors = signal<string[]>([]);
  protected readonly message = signal('');
  protected readonly panelOpen = computed(() => this.creating() || this.selectedId() !== null);
  /** One value object per alert, so the promote form keeps edits until another alert is opened. */
  protected readonly promotion = computed(() => {
    const alert = this.detail();
    if (!alert) return {};
    const severity = incidentSeverityFor(alert.severity);
    return {
      title: alert.title,
      severity,
      priority: severity,
      category: alert.source === PENTEST_SOURCE ? 7 : 9,
    };
  });
  protected searchText = this.filters().search;
  private readonly reload = new Subject<void>();
  private detailRequest?: Subscription;

  constructor() {
    // Keep the search box in step with back/forward navigation.
    effect(() => (this.searchText = this.filters().search));
    const poll = timer(30_000, 30_000).pipe(filter(() => !document.hidden && !this.busy()));
    // queryParamMap emits the current value on subscribe, which starts the first load.
    merge(this.route.queryParamMap, this.reload, poll)
      .pipe(
        switchMap(() => {
          this.loading.set(true);
          const params = this.route.snapshot.queryParamMap;
          const page = Number(params.get('page'));
          return this.alerts
            .list(
              Number.isSafeInteger(page) && page > 0 ? page : 1,
              25,
              this.apiFilters(readAlertFilters(params)),
            )
            .pipe(finalize(() => this.loading.set(false)));
        }),
        takeUntilDestroyed(),
      )
      .subscribe({
        next: (result) => {
          this.rows.set(result.items);
          this.page.set(result.page);
          this.pages.set(result.totalPages);
          this.total.set(result.totalCount);
        },
        error: (e) => this.errors.set(apiErrors(e)),
      });
    this.route.paramMap.pipe(takeUntilDestroyed()).subscribe((params) => {
      const id = selectedAlertId(params);
      this.detailRequest?.unsubscribe();
      this.detail.set(null);
      if (id === null) return;
      this.creating.set(false);
      this.detailLoading.set(true);
      this.detailRequest = this.alerts
        .detail(id)
        .pipe(
          finalize(() => this.detailLoading.set(false)),
          takeUntilDestroyed(this.destroy),
        )
        .subscribe({
          next: (a) => this.detail.set(a),
          error: (e) => this.errors.set(apiErrors(e)),
        });
    });
  }

  protected isOpen(alert: AlertSummary): boolean {
    return OPEN_STATUSES.includes(alert.status);
  }
  protected severityClass(text: string): string {
    const known = alertSeverityOptions.findIndex(
      (s) => s.toLowerCase() === text?.trim().toLowerCase(),
    );
    return known < 0 ? 'badge neutral' : `badge severity-${incidentSeverityFor(text)}`;
  }
  protected apply(change: Partial<Record<keyof AlertFilters | 'direction', string | null>>): void {
    const { direction, ...rest } = change;
    const queryParams: Record<string, string | null> = { page: null };
    for (const [key, value] of Object.entries(rest)) queryParams[key] = value || null;
    if (direction) queryParams['dir'] = direction;
    void this.router.navigate([], {
      relativeTo: this.route,
      queryParams,
      queryParamsHandling: 'merge',
    });
  }
  protected clear(): void {
    this.searchText = '';
    void this.router.navigate([], { relativeTo: this.route, queryParams: {} });
  }
  protected go(page: number): void {
    void this.router.navigate([], {
      relativeTo: this.route,
      queryParams: { page },
      queryParamsHandling: 'merge',
    });
  }
  protected startCreate(): void {
    this.errors.set([]);
    this.message.set('');
    if (this.selectedId() !== null)
      void this.router.navigate(['/alerts'], { queryParamsHandling: 'preserve' });
    this.creating.set(true);
  }
  protected closePanel(): void {
    this.creating.set(false);
    void this.router.navigate(['/alerts'], { queryParamsHandling: 'preserve' });
  }
  protected create(value: Record<string, unknown>): void {
    if (this.busy()) return;
    const data = { ...value };
    if (data['rawPayload']) {
      try {
        JSON.parse(String(data['rawPayload']));
      } catch {
        this.errors.set(['Original payload must be valid JSON.']);
        return;
      }
    } else data['rawPayload'] = null;
    data['detectedAt'] = new Date(String(data['detectedAt'])).toISOString();
    this.run(this.alerts.create(data), (created) => {
      this.creating.set(false);
      this.message.set('Alert created.');
      this.reload.next();
      void this.router.navigate(['/alerts', created.id], { queryParamsHandling: 'preserve' });
    });
  }
  protected promote(alert: AlertDetail, value: Record<string, unknown>): void {
    const request = {
      title: String(value['title']),
      severity: Number(value['severity']),
      priority: Number(value['priority']),
      category: Number(value['category']),
    };
    this.run(
      this.alerts.promote(alert.id, request),
      (incident) => void this.router.navigate(['/incidents', incident.id]),
    );
  }
  protected falsePositive(alert: AlertDetail, value: Record<string, unknown>): void {
    this.run(this.alerts.falsePositive(alert.id, String(value['reason'])), (updated) => {
      this.detail.set(updated);
      this.message.set(`Alert #${updated.id} marked as false positive.`);
      this.reload.next();
    });
  }
  private run<T>(request: Observable<T>, next: (value: T) => void): void {
    if (this.busy()) return;
    this.busy.set(true);
    this.errors.set([]);
    this.message.set('');
    request
      .pipe(
        finalize(() => this.busy.set(false)),
        takeUntilDestroyed(this.destroy),
      )
      .subscribe({ next, error: (e) => this.errors.set(apiErrors(e)) });
  }
  private apiFilters(f: AlertFilters): Record<string, string | number | boolean> {
    return {
      search: f.search,
      status: f.status,
      source: f.source,
      severity: f.severity,
      openOnly: f.open && !f.status ? true : '',
      sort: f.sort,
      direction: f.sort ? (f.dir === 'asc' ? 'asc' : 'desc') : '',
    };
  }
}
