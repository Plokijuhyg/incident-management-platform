import { InfoPopup } from '../../shared/components/detail-modal';
import { Component, DestroyRef, inject, signal } from '@angular/core';
import { HttpClient, HttpParams } from '@angular/common/http';
import { FormsModule } from '@angular/forms';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { finalize, Subscription } from 'rxjs';
import { ErrorNotice } from '../../shared/components/error-notice';
import { Page } from '../../core/models/api';
import { RecordRow } from '../../core/models/catalog';
import { apiErrors } from '../../core/services/api-errors';
import { utcTimestamp } from '../../core/services/incidents';
@Component({
  imports: [InfoPopup,FormsModule, ErrorNotice],
  template: `<div class="page-heading">
      <div>
        <p class="eyebrow">ACCOUNTABILITY & TRACEABILITY</p>
        <h1>Audit trail</h1>
        <p class="muted">A chronological record of access, changes and security decisions.</p>
      </div>
      <span class="badge neutral">Read only</span>
    </div>
    <app-error-notice [messages]="errors()" />
    <section class="panel">
      <form class="filter-bar" (ngSubmit)="load(1)">
        <div>
          <label for="audit-action">Action</label
          ><input
            id="audit-action"
            name="action"
            [(ngModel)]="action"
            placeholder="e.g. INCIDENT_CREATED"
          />
        </div>
        <div>
          <label for="audit-entity">Entity type</label
          ><input
            id="audit-entity"
            name="entity"
            [(ngModel)]="entity"
            placeholder="e.g. Incident"
          />
        </div>
        <div>
          <label for="audit-id">Entity ID</label
          ><input id="audit-id" name="id" [(ngModel)]="entityId" />
        </div>
        <div>
          <label for="audit-outcome">Outcome</label
          ><select id="audit-outcome" name="outcome" [(ngModel)]="outcome">
            <option value="">All</option>
            <option value="0">Success</option>
            <option value="1">Failure</option>
            <option value="2">Denied</option>
          </select>
        </div>
        <button class="button secondary" [disabled]="loading()">Apply filters</button>
      </form>
      @if (loading()) {
        <p class="empty-state" role="status">Loading audit trail...</p>
      } @else if (page(); as data) {
        <div class="table-scroll">
          <table>
            <thead>
              <tr>
                <th>When</th>
                <th>Actor</th>
                <th>Action</th>
                <th>Entity</th>
                <th>Outcome</th>
                <th>Details</th>
              </tr>
            </thead>
            <tbody>
              @for (row of data.items; track row.id) {
                <tr>
                  <td>{{ date(row['occurredAt']) }}</td>
                  <td>
                    {{ row['actorEmail'] || 'System / anonymous'
                    }}<small>{{ row['ipAddress'] }}</small>
                  </td>
                  <td>
                    <code>{{ row['action'] }}</code>
                  </td>
                  <td>{{ row['entityType'] }} {{ row['entityId'] }}</td>
                  <td>
                    <span
                      class="badge"
                      [class.severity-0]="row['outcome'] === 0"
                      [class.severity-3]="row['outcome'] !== 0"
                      >{{ outcomes[number(row['outcome'])] }}</span
                    >
                  </td>
                  <td>
                    <app-info-popup title="Inspect"><span popupTrigger>Inspect</span>
                      <pre class="raw-output">{{ row['details'] || 'No additional details.' }}</pre>
                    </app-info-popup>
                  </td>
                </tr>
              } @empty {
                <tr>
                  <td colspan="6">
                    <p class="empty-state">No audit entries match these filters.</p>
                  </td>
                </tr>
              }
            </tbody>
          </table>
        </div>
        <footer class="pagination">
          <span
            >{{ data.totalCount }} entries &middot; Page {{ data.page }} of
            {{ data.totalPages || 1 }}</span
          >
          <div>
            <button
              class="button secondary small"
              [disabled]="!data.hasPreviousPage"
              (click)="load(data.page - 1)"
            >
              Previous</button
            ><button
              class="button secondary small"
              [disabled]="!data.hasNextPage"
              (click)="load(data.page + 1)"
            >
              Next
            </button>
          </div>
        </footer>
      }
    </section>`,
})
export class AuditPage {
  private http = inject(HttpClient);
  private destroy = inject(DestroyRef);
  private request?: Subscription;
  protected page = signal<Page<RecordRow> | null>(null);
  protected errors = signal<string[]>([]);
  protected loading = signal(false);
  protected action = '';
  protected entity = '';
  protected entityId = '';
  protected outcome = '';
  protected outcomes = ['Success', 'Failure', 'Denied'];
  constructor() {
    this.load(1);
  }
  protected number(v: unknown) {
    return Number(v);
  }
  protected date(v: unknown) {
    return new Date(utcTimestamp(String(v))).toLocaleString();
  }
  protected load(page: number) {
    this.request?.unsubscribe();
    this.loading.set(true);
    this.errors.set([]);
    let params = new HttpParams().set('page', page).set('pageSize', 25);
    for (const [key, value] of Object.entries({
      action: this.action,
      entityType: this.entity,
      entityId: this.entityId,
      outcome: this.outcome,
    }))
      if (value) params = params.set(key, value);
    this.request = this.http
      .get<Page<RecordRow>>('/api/audit-logs', { params })
      .pipe(
        takeUntilDestroyed(this.destroy),
        finalize(() => this.loading.set(false)),
      )
      .subscribe({
        next: (v) => this.page.set(v),
        error: (e) => {
          this.page.set(null);
          this.errors.set(apiErrors(e));
        },
      });
  }
}
