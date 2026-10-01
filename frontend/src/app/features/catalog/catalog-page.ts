import { InfoPopup } from '../../shared/components/detail-modal';
import { IntelPanel } from '../../shared/components/intel-panel';
import { Component, DestroyRef, inject, signal } from '@angular/core';
import { HttpClient, HttpParams } from '@angular/common/http';
import { ActivatedRoute, RouterLink, Router } from '@angular/router';
import { FormsModule } from '@angular/forms';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { finalize, Subscription } from 'rxjs';
import {
  Catalog,
  catalogs,
  RecordRow,
  alertSources,
  alertStatuses,
  iocTypes,
  confidence,
  selectField,
  textField,
} from '../../core/models/catalog';
import { Page, categories, priorities, severities } from '../../core/models/api';
import { Auth } from '../../core/services/auth';
import { apiErrors } from '../../core/services/api-errors';
import { utcTimestamp } from '../../core/services/incidents';
import { DataForm, Field } from '../../shared/components/data-form';
import { ErrorNotice } from '../../shared/components/error-notice';
@Component({
  imports: [InfoPopup,IntelPanel,FormsModule, RouterLink, DataForm, ErrorNotice],
  template: `
    <div class="page-heading">
      <div>
        <p class="eyebrow">{{ config.eyebrow }}</p>
        <h1>{{ config.title }}</h1>
        <p class="muted">{{ config.intro }}</p>
      </div>
      @if(kind==='assets' && auth.hasRole('ADMIN')){<button class="button secondary" [disabled]="busy()" (click)="syncSources()">Sync log sources &amp; lab targets</button>}
      @if (canCreate()) {
        <button class="button" (click)="create()">+ New {{ singular() }}</button>
      }
    </div>
    <app-error-notice [messages]="errors()" />
    @if (message()) {
      <p class="success-notice" role="status">{{ message() }}</p>
    }
    @if(kind==='alerts' && detail();as intelRecord){<app-intel-panel kind="alerts" [recordId]="intelRecord.id" />}
    @if (detail() || creating()) {
      <button class="back-link link-button" (click)="back()">
        &larr; Back to {{ config.title }}
      </button>
      <div class="create-grid">
        <section class="panel panel-padding">
          @if (creating()) {
            <h2>New {{ singular() }}</h2>
            <app-data-form
              [fields]="config.fields"
              [busy]="busy()"
              label="Create record"
              (saved)="save($event)"
            />
          } @else if (detail(); as row) {
            <p class="eyebrow">{{ kind === 'mitre' ? row['techniqueId'] : '#' + row.id }}</p>
            <h2 class="break-word">{{ row['title'] || row['name'] || row['value'] }}</h2>
            <p class="description">{{ row['description'] || 'No description provided.' }}</p>
              @if (kind === 'alerts' && row['recommendedAction']) {
                <h3>Recommended response</h3>
                <p class="notice">Suggestion only. Human review is required; no action has been executed.</p>
                <p>{{ row['recommendedAction'] }}</p>
              }
            <dl class="record-facts">
              @for (col of config.columns; track col.key) {
                <dt>{{ col.label }}</dt>
                <dd>{{ display(row, col.key, col.values) }}</dd>
              }
            </dl>
            @if (row['rawPayload']) {
              <app-info-popup title="Original evidence / tool output"><span popupTrigger>Original evidence / tool output</span>
                <pre class="raw-output">{{ row['rawPayload'] }}</pre>
              </app-info-popup>
            }
            @if (kind === 'alerts' && row['source'] === 6) {
              <p class="notice">
                PenTest signal. Original payload is tool evidence; descriptions may contain analyst
                or AI interpretation. Validate evidence before promotion.
              </p>
            }
            @if (canEdit()) {
              <hr />
              <h3>Edit {{ singular() }}</h3>
              <app-data-form
                [fields]="config.editFields"
                [value]="row"
                [busy]="busy()"
                (saved)="save($event)"
              />
            }
            @if (kind === 'alerts' && row['incidentId']) {
              <a class="button secondary" [routerLink]="['/incidents', row['incidentId']]"
                >Open linked incident &rarr;</a
              >
            }
            @if (kind === 'alerts' && (row['status'] === 0 || row['status'] === 1)) {
              <hr />
              <h3>Promote to incident</h3>
              <p class="muted">
                Choose the incident severity and response priority after reviewing the evidence.
              </p>
              <app-data-form
                [fields]="promoteFields"
                [value]="promotionValue(row)"
                [busy]="busy()"
                label="Promote to incident"
                (saved)="promote($event)"
              />
              <hr />
              <h3>Mark false positive</h3>
              <app-data-form
                [fields]="reasonFields"
                [busy]="busy()"
                label="Confirm false positive"
                (saved)="falsePositive($event)"
              />
            }
            @if (appearances(row).length) {
              <hr />
              <h3>Related incidents</h3>
              @for (item of appearances(row); track item['incidentId']) {
                <a class="related-card" [routerLink]="['/incidents', item['incidentId']]"
                  >{{ item['incidentNumber'] }} &middot; {{ item['title'] }} &rarr;</a
                >
              }
            }
          }
        </section>
        <aside class="creation-notes">
          <h2>{{ kind === 'alerts' ? 'A signal is a starting point' : 'Connected context' }}</h2>
          <p>
            {{
              kind === 'alerts'
                ? 'Review the source and evidence, determine impact, and promote actionable signals into incidents.'
                : 'Use incident associations to connect this record to an investigation. The catalog remains shared across the workspace.'
            }}
          </p>
          <a routerLink="/incidents">Open investigations &rarr;</a>
        </aside>
      </div>
    } @else {
      <section class="panel">
        <form class="filter-bar" (ngSubmit)="load(1)">
          @if (kind === 'iocs' || kind === 'mitre') {
            <div>
              <label for="catalog-search">Search</label
              ><input
                id="catalog-search"
                name="search"
                [(ngModel)]="search"
                placeholder="Search the catalog..."
              />
            </div>
          }
          @if (kind === 'alerts') {
            <div>
              <label for="filter-status">Status</label
              ><select id="filter-status" name="status" [(ngModel)]="status">
                <option value="">All statuses</option>
                @for (label of alertStatuses; track $index) {
                  <option [value]="$index">{{ label }}</option>
                }
              </select>
            </div>
            <div>
              <label for="filter-source">Source</label
              ><select id="filter-source" name="source" [(ngModel)]="source">
                <option value="">All sources</option>
                @for (label of alertSources; track $index) {
                  <option [value]="$index">{{ label }}</option>
                }
              </select>
            </div>
          }
          @if (kind === 'iocs') {
            <div>
              <label for="filter-type">Type</label
              ><select id="filter-type" name="type" [(ngModel)]="type">
                <option value="">All types</option>
                @for (label of iocTypes; track $index) {
                  <option [value]="$index">{{ label }}</option>
                }
              </select>
            </div>
            <div>
              <label for="filter-confidence">Confidence</label
              ><select id="filter-confidence" name="confidence" [(ngModel)]="certainty">
                <option value="">All confidence levels</option>
                @for (label of confidence; track $index) {
                  <option [value]="$index">{{ label }}</option>
                }
              </select>
            </div>
            <div>
              <label for="filter-verdict">Verdict</label
              ><select id="filter-verdict" name="verdict" [(ngModel)]="verdict">
                <option value="">Any verdict</option>
                <option value="true">Malicious</option>
                <option value="false">Benign</option>
              </select>
            </div>
          }
          @if (kind === 'mitre') {
            <div>
              <label for="filter-tactic">Tactic</label
              ><select id="filter-tactic" name="tactic" [(ngModel)]="tactic">
                <option value="">All tactics</option>
                @for (item of tactics(); track item) {
                  <option [value]="item">{{ item }}</option>
                }
              </select>
            </div>
            <label class="inline-check"
              ><input type="checkbox" name="sub" [(ngModel)]="includeSub" /> Include
              sub-techniques</label
            >
          }
          <button class="button secondary" [disabled]="loading()">
            {{ kind === 'assets' ? 'Refresh' : 'Apply filters' }}
          </button>
        </form>
        @if (loading()) {
          <div class="empty-state" role="status">Loading {{ config.title.toLowerCase() }}...</div>
        } @else if (rows().length) {
          <div class="table-scroll">
            <table>
              <thead>
                <tr>
                  @for (col of config.columns; track col.key) {
                    <th>{{ col.label }}</th>
                  }
                  <th><span class="sr-only">Open record</span></th>
                </tr>
              </thead>
              <tbody>
                @for (row of rows(); track row.id) {
                  <tr>
                    @for (col of config.columns; track col.key) {
                      <td>
                        @if ($first) {
                          <a
                            [routerLink]="[
                              '/',
                              kind === 'mitre' ? 'attack-matrix' : kind,
                              kind === 'mitre' ? row['techniqueId'] : row.id,
                            ]"
                            >{{ display(row, col.key, col.values) }}</a
                          >
                        } @else {
                          <span
                            [class]="
                              col.key === 'severity' ? 'badge severity-' + severityClass(row) : ''
                            "
                            >{{ display(row, col.key, col.values) }}</span
                          >
                        }
                      </td>
                    }
                    <td>
                      <a
                        [routerLink]="['/', kind === 'mitre' ? 'attack-matrix' : kind, kind === 'mitre' ? row['techniqueId'] : row.id]"
                        [attr.aria-label]="'Open record ' + row.id"
                        >View &rarr;</a
                      >
                    </td>
                  </tr>
                }
              </tbody>
            </table>
          </div>
        } @else {
          <div class="empty-state">
            <div class="empty-symbol">&#9678;</div>
            <h2>No matching records</h2>
            <p>New records will appear here. Try adjusting your filters.</p>
          </div>
        }
        <footer class="pagination">
          <span>{{ total() }} records &middot; Page {{ page() }} of {{ pages() || 1 }}</span>
          <div>
            <button
              class="button secondary small"
              [disabled]="page() <= 1 || loading()"
              (click)="load(page() - 1)"
            >
              Previous</button
            ><button
              class="button secondary small"
              [disabled]="page() >= pages() || loading()"
              (click)="load(page() + 1)"
            >
              Next
            </button>
          </div>
        </footer>
      </section>
      @if (kind === 'iocs') {
        <section class="panel panel-padding">
          <h2>Have we seen this before?</h2>
          <p class="muted">Exact indicator lookup, including server normalization.</p>
          <app-data-form
            [fields]="lookupFields"
            label="Look up indicator"
            [busy]="busy()"
            (saved)="lookup($event)"
          />
        </section>
      }
    }
  `,
})
export class CatalogPage {
  protected syncSources(){if(this.busy())return;this.busy.set(true);this.http.post<{added:number;message:string}>('/api/assets/sync-sources',{}).pipe(finalize(()=>this.busy.set(false)),takeUntilDestroyed(this.destroy)).subscribe({next:r=>{this.message.set(r.message);this.load(1);},error:e=>this.errors.set(apiErrors(e))});}

  private readonly route = inject(ActivatedRoute);
  private readonly router = inject(Router);
  private readonly http = inject(HttpClient);
  private readonly destroy = inject(DestroyRef);
  protected readonly auth = inject(Auth);
  protected kind = this.route.snapshot.data['kind'] as string;
  protected config: Catalog = catalogs[this.kind];
  protected readonly rows = signal<RecordRow[]>([]);
  protected readonly detail = signal<RecordRow | null>(null);
  protected readonly creating = signal(false);
  protected readonly loading = signal(false);
  protected readonly busy = signal(false);
  protected readonly errors = signal<string[]>([]);
  protected readonly message = signal('');
  protected readonly page = signal(1);
  protected readonly pages = signal(1);
  protected readonly total = signal(0);
  protected readonly tactics = signal<string[]>([]);
  protected search = '';
  protected status = '';
  protected source = '';
  protected type = '';
  protected certainty = '';
  protected verdict = '';
  protected tactic = '';
  protected includeSub = true;
  private all: RecordRow[] = [];
  private listRequest?: Subscription;
  private detailRequest?: Subscription;
  protected readonly alertSources = alertSources;
  protected readonly alertStatuses = alertStatuses;
  protected readonly iocTypes = iocTypes;
  protected readonly confidence = confidence;
  protected readonly lookupFields = [
    selectField('type', 'Type', iocTypes),
    textField('value', 'Indicator value', true, 512),
  ];
  protected readonly reasonFields: Field[] = [
    { key: 'reason', label: 'Reason', type: 'textarea', required: true },
  ];
  protected readonly promoteFields: Field[] = [
    textField('title', 'Incident title', true),
    selectField('severity', 'Severity', severities, 1),
    selectField('priority', 'Priority', priorities, 1),
    selectField('category', 'Category', categories, 7),
  ];
  constructor() {
    this.route.paramMap.pipe(takeUntilDestroyed()).subscribe((p) => {
      this.detailRequest?.unsubscribe();
      this.detail.set(null);
      this.creating.set(false);
      this.errors.set([]);
      const id = p.get('id');
      if (id) this.open(id);
      else this.load(1);
    });
    if (this.kind === 'mitre')
      this.http
        .get<string[]>('/api/mitre/tactics')
        .pipe(takeUntilDestroyed())
        .subscribe({
          next: (v) => this.tactics.set(v),
          error: (e) => this.errors.set(apiErrors(e)),
        });
  }
  protected singular() {
    return this.kind === 'iocs' ? 'indicator' : this.kind === 'assets' ? 'asset' : 'alert';
  }
  protected canCreate() {
    return (
      this.config.fields.length > 0 && (this.kind !== 'assets' || this.auth.canManageIncidents())
    );
  }
  protected canEdit() {
    return (
      this.config.editFields.length > 0 &&
      (this.kind !== 'assets' || this.auth.canManageIncidents())
    );
  }
  protected create() {
    this.creating.set(true);
    this.detail.set(null);
    this.errors.set([]);
    this.message.set('');
  }
  protected back() {
    this.creating.set(false);
    this.detail.set(null);
    void this.router.navigate(['/', this.kind === 'mitre' ? 'attack-matrix' : this.kind]);
    this.load(1);
  }
  protected display(row: RecordRow, key: string, values?: string[]) {
    const v = row[key];
    if (values) return values[Number(v)] ?? 'Unknown';
    if (v === null || v === undefined || v === '')
      return key === 'isMalicious' ? 'Unverified' : 'Not recorded';
    if (typeof v === 'boolean')
      return key === 'isMalicious'
        ? v
          ? 'Malicious'
          : 'Benign'
        : key === 'isActive'
          ? v
            ? 'Active'
            : 'Inactive'
          : v
            ? 'Yes'
            : 'No';
    if (key.endsWith('At')) return new Date(utcTimestamp(String(v))).toLocaleString();
    return String(v);
  }
  protected severityClass(row: RecordRow) {
    return severities.findIndex((x) => x.toLowerCase() === String(row['severity']).toLowerCase());
  }
  protected appearances(row: RecordRow): RecordRow[] {
    return Array.isArray(row['incidents']) ? (row['incidents'] as RecordRow[]) : [];
  }
  private promotionId = 0;
  private promotion: Record<string, unknown> = {};
  protected promotionValue(row: RecordRow) {
    if (this.promotionId !== row.id) {
      this.promotionId = row.id;
      this.promotion = { title: row['title'] };
    }
    return this.promotion;
  }
  protected load(page: number) {
    this.listRequest?.unsubscribe();
    if (this.kind === 'mitre' && page !== 1) {
      this.page.set(page);
      this.rows.set(this.all.slice((page - 1) * 25, page * 25));
      return;
    }
    this.loading.set(true);
    this.errors.set([]);
    this.page.set(page);
    let params = new HttpParams().set('page', page).set('pageSize', 25);
    for (const [key, v] of Object.entries({
      search: this.search,
      status: this.status,
      source: this.source,
      type: this.type,
      confidence: this.certainty,
      isMalicious: this.verdict,
      tactic: this.tactic,
    }))
      if (v !== '') params = params.set(key, v);
    if (this.kind === 'mitre') params = params.set('includeSubTechniques', this.includeSub);
    this.listRequest = this.http
      .get<Page<RecordRow> | RecordRow[]>(this.config.endpoint, { params })
      .pipe(
        takeUntilDestroyed(this.destroy),
        finalize(() => this.loading.set(false)),
      )
      .subscribe({
        next: (r) => {
          if (Array.isArray(r)) {
            this.all = r;
            this.rows.set(r.slice(0, 25));
            this.total.set(r.length);
            this.pages.set(Math.ceil(r.length / 25));
          } else {
            this.rows.set(r.items);
            this.total.set(r.totalCount);
            this.pages.set(r.totalPages);
          }
        },
        error: (e) => {
          this.rows.set([]);
          this.errors.set(apiErrors(e));
        },
      });
  }
  private open(id: string) {
    this.detailRequest?.unsubscribe();
    this.loading.set(true);
    this.detailRequest = this.http
      .get<RecordRow>(this.config.endpoint + '/' + encodeURIComponent(id))
      .pipe(
        takeUntilDestroyed(this.destroy),
        finalize(() => this.loading.set(false)),
      )
      .subscribe({ next: (r) => this.detail.set(r), error: (e) => this.errors.set(apiErrors(e)) });
  }
  protected save(value: Record<string, unknown>) {
    if (this.busy()) return;
    this.errors.set([]);
    const data = { ...value };
    if (this.kind === 'alerts') {
      if (data['rawPayload']) {
        try {
          JSON.parse(String(data['rawPayload']));
        } catch {
          this.errors.set(['Original payload must be valid JSON.']);
          return;
        }
      } else data['rawPayload'] = null;
      data['detectedAt'] = new Date(String(data['detectedAt'])).toISOString();
    }
    if (data['isMalicious'] === '') data['isMalicious'] = null;
    const id = this.detail()?.id;
    this.busy.set(true);
    (id
      ? this.http.put<RecordRow>(this.config.endpoint + '/' + id, data)
      : this.http.post<RecordRow>(this.config.endpoint, data)
    )
      .pipe(
        takeUntilDestroyed(this.destroy),
        finalize(() => this.busy.set(false)),
      )
      .subscribe({
        next: (r) => {
          this.message.set('Record saved.');
          if (id) this.open(String(id));
          else {
            this.creating.set(false);
            void this.router.navigate(['/', this.kind, r.id]);
          }
        },
        error: (e) => this.errors.set(apiErrors(e)),
      });
  }
  protected promote(value: Record<string, unknown>) {
    this.action('promote', value, (r) => void this.router.navigate(['/incidents', r.id]));
  }
  protected falsePositive(value: Record<string, unknown>) {
    this.action('false-positive', value, (r) => {
      this.detail.set(r);
      this.message.set('Alert marked as false positive.');
    });
  }
  private action(name: string, value: unknown, next: (r: RecordRow) => void) {
    if (this.busy()) return;
    this.busy.set(true);
    this.errors.set([]);
    this.http
      .post<RecordRow>(this.config.endpoint + '/' + this.detail()!.id + '/' + name, value)
      .pipe(
        takeUntilDestroyed(this.destroy),
        finalize(() => this.busy.set(false)),
      )
      .subscribe({ next, error: (e) => this.errors.set(apiErrors(e)) });
  }
  protected lookup(value: Record<string, unknown>) {
    if (this.busy()) return;
    this.busy.set(true);
    this.errors.set([]);
    this.http
      .get<RecordRow>('/api/iocs/lookup', {
        params: { type: Number(value['type']), value: String(value['value']) },
      })
      .pipe(
        takeUntilDestroyed(this.destroy),
        finalize(() => this.busy.set(false)),
      )
      .subscribe({
        next: (r) => void this.router.navigate(['/iocs', r.id]),
        error: (e) =>
          this.errors.set(
            e.status === 404 ? ['This indicator has not been recorded.'] : apiErrors(e),
          ),
      });
  }
}
