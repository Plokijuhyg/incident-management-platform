import { DatePipe } from '@angular/common';
import { Component, computed, effect, inject } from '@angular/core';
import { toSignal } from '@angular/core/rxjs-interop';
import { FormsModule } from '@angular/forms';
import { ActivatedRoute, ParamMap, Router, RouterLink } from '@angular/router';
import { Subject, catchError, combineLatest, map, of, startWith, switchMap } from 'rxjs';
import {
  IncidentSummary,
  LoadState,
  Page,
  categories,
  severities,
  statuses,
} from '../../core/models/api';
import { Auth } from '../../core/services/auth';
import { Incidents } from '../../core/services/incidents';
import { apiErrors } from '../../core/services/api-errors';
import { ErrorNotice } from '../../shared/components/error-notice';
import { SeverityBadge } from '../../shared/components/severity-badge';
import { SortHeader, SortState } from '../../shared/components/sort-header';

export function pageNumber(value: string | null): number {
  const page = Number(value ?? 1);
  return Number.isSafeInteger(page) && page > 0 && page <= 1_000_000 ? page : 1;
}
@Component({
  imports: [DatePipe, FormsModule, RouterLink, ErrorNotice, SeverityBadge, SortHeader],
  template: ` <div class="page-heading">
      <div>
        <p class="eyebrow">INCIDENT RESPONSE</p>
        <h1>Incidents</h1>
        <p class="muted">Investigate activity. Track the response. Keep your team aligned.</p>
      </div>
      <a class="button" routerLink="/incidents/new"
        ><span aria-hidden="true">+</span> New incident</a
      >
    </div>
    <section class="panel">
      <div class="panel-heading">
        <div>
          <h2>Incident register</h2>
          <p class="muted small-text">Filters, sorting and page are kept in the address bar.</p>
        </div>
        <button class="button secondary small" (click)="reload.next()" [disabled]="state().loading">
          Refresh
        </button>
      </div>
      <form class="filter-bar" role="search" (ngSubmit)="apply({ search: searchText.trim() })">
        <div>
          <label for="incident-search">Search</label
          ><input
            id="incident-search"
            name="search"
            type="search"
            maxlength="200"
            [(ngModel)]="searchText"
            placeholder="Title, INC number or description"
          />
        </div>
        <div>
          <label for="incident-status">Status</label
          ><select
            id="incident-status"
            [ngModel]="filters().status"
            name="status"
            (ngModelChange)="apply({ status: $event })"
          >
            <option value="">Any status</option>
            @for (label of statuses; track $index) {
              <option [value]="'' + $index">{{ label }}</option>
            }
          </select>
        </div>
        <div>
          <label for="incident-severity">Severity</label
          ><select
            id="incident-severity"
            [ngModel]="filters().severity"
            name="severity"
            (ngModelChange)="apply({ severity: $event })"
          >
            <option value="">Any severity</option>
            @for (label of severities; track $index) {
              <option [value]="'' + $index">{{ label }}</option>
            }
          </select>
        </div>
        <div>
          <label for="incident-assignee">Assignee</label
          ><select
            id="incident-assignee"
            [ngModel]="filters().assignee"
            name="assignee"
            (ngModelChange)="apply({ assignee: $event })"
          >
            <option value="">Anyone</option>
            <option value="me">Assigned to me</option>
            <option value="unassigned">Unassigned</option>
          </select>
        </div>
        <div>
          <label for="incident-tier">Tier</label
          ><select
            id="incident-tier"
            [ngModel]="filters().tier"
            name="tier"
            (ngModelChange)="apply({ tier: $event })"
          >
            <option value="">Any tier</option>
            <option value="1">Tier 1</option>
            <option value="2">Tier 2</option>
            <option value="3">Tier 3</option>
          </select>
        </div>
        <label class="inline-check"
          ><input
            type="checkbox"
            name="open"
            [ngModel]="filters().open"
            (ngModelChange)="apply({ open: $event ? 'true' : '' })"
          />
          Open only</label
        ><label class="inline-check"
          ><input
            type="checkbox"
            name="sla"
            [ngModel]="filters().sla"
            (ngModelChange)="apply({ sla: $event ? 'true' : '' })"
          />
          SLA breached</label
        >
        <button class="button secondary">Search</button>
        @if (filtered()) {
          <button type="button" class="link-button" (click)="clear()">Clear filters</button>
        }
      </form>
      @if (state().loading) {
        <div class="empty-state" role="status">Loading incidents...</div>
      }
      <app-error-notice [messages]="state().errors" />
      @if (state().errors.length) {
        <div class="panel-padding">
          <button class="button secondary" (click)="reload.next()">Try again</button>
        </div>
      }
      @if (state().data; as page) {
        @if (page.items.length) {
          <div class="table-scroll">
            <table>
              <caption class="sr-only">
                Incidents, page
                {{
                  page.page
                }}
                of
                {{
                  page.totalPages
                }}
              </caption>
              <thead>
                <tr>
                  <th
                    sortKey="incidentNumber"
                    firstDirection="asc"
                    [state]="sort()"
                    (sorted)="apply($event)"
                  >
                    Incident
                  </th>
                  <th sortKey="severity" [state]="sort()" (sorted)="apply($event)">Severity</th>
                  <th
                    sortKey="status"
                    firstDirection="asc"
                    [state]="sort()"
                    (sorted)="apply($event)"
                  >
                    Status
                  </th>
                  <th scope="col">Tier</th>
                  <th scope="col">Category</th>
                  <th scope="col">Assignee</th>
                  <th sortKey="createdAt" [state]="sort()" (sorted)="apply($event)">Created</th>
                  <th scope="col">SLA</th>
                </tr>
              </thead>
              <tbody>
                @for (incident of page.items; track incident.id) {
                  <tr>
                    <td>
                      <a class="incident-link" [routerLink]="['/incidents', incident.id]"
                        ><span class="incident-number">{{ incident.incidentNumber }}</span
                        ><strong>{{ incident.title }}</strong></a
                      >
                    </td>
                    <td><app-severity [value]="incident.severity" /></td>
                    <td>
                      <span class="badge neutral">{{
                        statuses.at(incident.status) ?? 'Unknown'
                      }}</span>
                    </td>
                    <td>
                      <span class="badge neutral">T{{ incident.tier }}</span>
                    </td>
                    <td>{{ categories.at(incident.category) ?? 'Unknown' }}</td>
                    <td>{{ incident.assignedToName || 'Unassigned' }}</td>
                    <td class="nowrap">{{ incident.createdAt | date: 'MMM d, y, HH:mm' }}</td>
                    <td class="nowrap">
                      @if (incident.slaDueAt && isOpen(incident) && breached(incident.slaDueAt)) {
                        <span class="badge severity-3">Breached</span>
                      } @else if (incident.slaDueAt && isOpen(incident)) {
                        <span class="muted small-text">{{
                          incident.slaDueAt | date: 'MMM d, HH:mm'
                        }}</span>
                      } @else {
                        <span class="muted">—</span>
                      }
                    </td>
                  </tr>
                }
              </tbody>
            </table>
          </div>
        } @else {
          <div class="empty-state">
            <span class="empty-icon" aria-hidden="true">&#9636;</span>
            <h2>
              {{
                page.totalCount
                  ? 'No incidents on this page'
                  : filtered()
                    ? 'No incidents match these filters'
                    : 'No incidents yet'
              }}
            </h2>
            <p>
              {{
                page.totalCount
                  ? 'Go back to the first page to view the incident register.'
                  : filtered()
                    ? 'Try a broader search or clear the filters.'
                    : 'Create your first incident to start tracking a response.'
              }}
            </p>
            @if (page.totalCount) {
              <button class="button secondary" (click)="go(1)">First page</button>
            } @else if (filtered()) {
              <button class="button secondary" (click)="clear()">Clear filters</button>
            } @else {
              <a class="button" routerLink="/incidents/new">Create an incident</a>
            }
          </div>
        }
        <footer class="pagination">
          <span
            >{{ page.totalCount }} {{ page.totalCount === 1 ? 'incident' : 'incidents' }}
            <span class="divider">&middot;</span> Page {{ page.page }} of
            {{ page.totalPages || 1 }}</span
          >
          <div>
            <button
              class="button secondary small"
              [disabled]="!page.hasPreviousPage"
              (click)="go(page.page - 1)"
            >
              &larr; Previous</button
            ><button
              class="button secondary small"
              [disabled]="!page.hasNextPage"
              (click)="go(page.page + 1)"
            >
              Next &rarr;
            </button>
          </div>
        </footer>
      }
    </section>`,
})
export class IncidentList {
  private readonly route = inject(ActivatedRoute);
  private readonly router = inject(Router);
  private readonly incidents = inject(Incidents);
  private readonly auth = inject(Auth);
  protected readonly reload = new Subject<void>();
  protected readonly categories = categories;
  protected readonly statuses = statuses;
  protected readonly severities = severities;
  private readonly params = toSignal(this.route.queryParamMap, {
    initialValue: this.route.snapshot.queryParamMap,
  });
  protected readonly filters = computed(() => readFilters(this.params()));
  protected readonly sort = computed<SortState>(() => ({
    sort: this.filters().sort || 'createdAt',
    direction: this.filters().dir === 'asc' ? 'asc' : 'desc',
  }));
  protected readonly filtered = computed(() => {
    const f = this.filters();
    return !!(f.search || f.status || f.severity || f.assignee || f.tier || f.open || f.sla);
  });
  protected searchText = this.filters().search;
  constructor() {
    // Keep the search box in step with back/forward navigation.
    effect(() => (this.searchText = this.filters().search));
  }
  protected isOpen(incident: IncidentSummary): boolean {
    // Open = not Resolved(6)/Closed(7)/FalsePositive(8).
    return incident.status < 6;
  }
  protected breached(slaDueAt: string): boolean {
    return new Date(slaDueAt).getTime() < Date.now();
  }
  protected readonly state = toSignal(
    combineLatest([this.route.queryParamMap, this.reload.pipe(startWith(undefined))]).pipe(
      switchMap(([params]) =>
        this.incidents
          .list(pageNumber(params.get('page')), 25, this.apiFilters(readFilters(params)))
          .pipe(
            map(
              (data) => ({ loading: false, data, errors: [] }) as LoadState<Page<IncidentSummary>>,
            ),
            catchError((error) => of({ loading: false, data: null, errors: apiErrors(error) })),
            startWith({ loading: true, data: null, errors: [] }),
          ),
      ),
    ),
    { initialValue: { loading: true, data: null, errors: [] } as LoadState<Page<IncidentSummary>> },
  );
  protected go(page: number): void {
    void this.router.navigate([], {
      relativeTo: this.route,
      queryParams: { page },
      queryParamsHandling: 'merge',
    });
  }
  /** Any filter or sort change starts again from page 1; empty values leave the URL. */
  protected apply(change: Partial<Record<keyof IncidentFilters | 'direction', string>>): void {
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
  private apiFilters(f: IncidentFilters): Record<string, string | number | boolean> {
    const result: Record<string, string | number | boolean> = {
      search: f.search,
      status: f.status,
      severity: f.severity,
      sort: f.sort,
      direction: f.sort ? (f.dir === 'asc' ? 'asc' : 'desc') : '',
    };
    if (f.open) result['openOnly'] = true;
    if (f.sla) result['slaBreached'] = true;
    if (f.tier) result['tier'] = f.tier;
    if (f.assignee === 'unassigned') result['unassigned'] = true;
    const me = this.auth.user()?.id;
    if (f.assignee === 'me' && me) result['assignedToId'] = me;
    return result;
  }
}

export interface IncidentFilters {
  search: string;
  status: string;
  severity: string;
  assignee: string;
  tier: string;
  open: boolean;
  sla: boolean;
  sort: string;
  dir: string;
}
const sortKeys = [
  'createdAt',
  'updatedAt',
  'severity',
  'priority',
  'status',
  'title',
  'incidentNumber',
];
/** Reads list state from the URL, discarding anything the API would reject. */
export function readFilters(params: ParamMap): IncidentFilters {
  const index = (value: string | null, max: number) =>
    value !== null && /^\d+$/.test(value) && Number(value) < max ? value : '';
  const sort = params.get('sort') ?? '';
  return {
    search: (params.get('search') ?? '').slice(0, 200),
    status: index(params.get('status'), statuses.length),
    severity: index(params.get('severity'), severities.length),
    assignee: ['me', 'unassigned'].includes(params.get('assignee') ?? '')
      ? params.get('assignee')!
      : '',
    tier: ['1', '2', '3'].includes(params.get('tier') ?? '') ? params.get('tier')! : '',
    open: params.get('open') === 'true',
    sla: params.get('sla') === 'true',
    sort: sortKeys.includes(sort) ? sort : '',
    dir: params.get('dir') === 'asc' ? 'asc' : params.get('dir') === 'desc' ? 'desc' : '',
  };
}
