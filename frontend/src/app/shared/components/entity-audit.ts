import { InfoPopup } from './detail-modal';
import { Component, DestroyRef, inject, input, OnChanges, signal } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { finalize, Subscription } from 'rxjs';
import { Page } from '../../core/models/api';
import { RecordRow } from '../../core/models/catalog';
import { apiErrors } from '../../core/services/api-errors';
import { ErrorNotice } from './error-notice';
@Component({
  selector: 'app-entity-audit',
  imports: [InfoPopup,ErrorNotice],
  template: `<section class="panel panel-padding">
    <h2>Incident audit history</h2>
    <app-error-notice [messages]="errors()" />
    @if (busy()) {
      <p role="status">Loading audit history...</p>
    }
    @for (row of page()?.items; track row.id) {
      <article class="activity-item">
        <strong>{{ row['action'] }}</strong>
        <p>{{ row['actorEmail'] || 'System' }} &middot; {{ row['occurredAt'] }}</p>
        <app-info-popup title="Changes"><span popupTrigger>Changes</span>
          <pre class="raw-output">{{ row['details'] }}</pre>
        </app-info-popup>
      </article>
    } @empty {
      <p>No audit entries loaded.</p>
    }
    <div class="pagination">
      <button
        class="button secondary small"
        [disabled]="busy() || !page()?.hasPreviousPage"
        (click)="load((page()?.page || 1) - 1)"
      >
        Previous</button
      ><span>Page {{ page()?.page || 1 }}</span
      ><button
        class="button secondary small"
        [disabled]="busy() || !page()?.hasNextPage"
        (click)="load((page()?.page || 1) + 1)"
      >
        Next
      </button>
    </div>
  </section>`,
})
export class EntityAudit implements OnChanges {
  readonly incidentId = input.required<number>();
  private http = inject(HttpClient);
  private destroy = inject(DestroyRef);
  private request?: Subscription;
  protected page = signal<Page<RecordRow> | null>(null);
  protected busy = signal(false);
  protected errors = signal<string[]>([]);
  ngOnChanges() {
    this.load(1);
  }
  protected load(page: number) {
    this.request?.unsubscribe();
    this.busy.set(true);
    this.errors.set([]);
    this.request = this.http
      .get<Page<RecordRow>>('/api/audit-logs/entity/Incident/' + this.incidentId(), {
        params: { page, pageSize: 25 },
      })
      .pipe(
        takeUntilDestroyed(this.destroy),
        finalize(() => this.busy.set(false)),
      )
      .subscribe({
        next: (p) => this.page.set(p),
        error: (e) => {
          this.page.set(null);
          this.errors.set(apiErrors(e));
        },
      });
  }
}
