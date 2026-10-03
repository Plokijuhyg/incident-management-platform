import { DatePipe } from '@angular/common';
import { Component, DestroyRef, inject, signal } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { RouterLink } from '@angular/router';
import { finalize } from 'rxjs';
import { apiErrors } from '../../core/services/api-errors';
import { ErrorNotice } from '../../shared/components/error-notice';

interface Entity {
  id: number;
  entityType: string;
  entityValue: string;
  riskScore: number;
  failedLoginsHour: number;
  eventCount: number;
  lastAnomaly: string | null;
  lastAnomalyAt: string | null;
  firstSeenAt: string;
  lastSeenAt: string;
}
interface EntityPage {
  total: number;
  withAnomalies: number;
  items: Entity[];
}
interface EntityDetail extends Entity {
  knownSourceIps: string[];
  knownSourceIpCount: number;
  recentAlerts: {
    id: number;
    title: string;
    severity: string;
    status: number;
    incidentId: number | null;
    detectedAt: string;
  }[];
}

/**
 * User/entity behavior analytics. Shows the riskiest entities from their rolling
 * baselines and the anomalies that raised their score. A high score is a lead to
 * investigate, never proof of compromise.
 */
@Component({
  imports: [DatePipe, RouterLink, ErrorNotice],
  template: `
    <div class="page-heading compact-heading">
      <div>
        <p class="eyebrow">BEHAVIOR ANALYTICS</p>
        <h1>UEBA</h1>
        <p class="muted small-text">
          Per-entity baselines from ingested logs. Anomalies (failed-login spikes, logins from new
          sources) raise an entity's risk and open alerts that feed correlation. A lead, not a
          verdict.
        </p>
      </div>
      <button class="button secondary small" (click)="load()" [disabled]="loading()">
        Refresh
      </button>
    </div>
    <app-error-notice [messages]="errors()" />
    @if (data(); as page) {
      <div class="log-stats">
        <div class="stat-card">
          <strong>{{ page.total }}</strong
          ><span>Tracked entities</span>
        </div>
        <div class="stat-card">
          <strong>{{ page.withAnomalies }}</strong
          ><span>With anomalies</span>
        </div>
      </div>
      <section class="panel">
        @if (page.items.length) {
          <div class="table-scroll">
            <table class="queue-table">
              <thead>
                <tr>
                  <th scope="col">Entity</th>
                  <th scope="col">Risk</th>
                  <th scope="col">Failed logins (hr)</th>
                  <th scope="col">Last anomaly</th>
                  <th scope="col">Last seen (UTC)</th>
                </tr>
              </thead>
              <tbody>
                @for (entity of page.items; track entity.id) {
                  <tr
                    [class.selected]="entity.id === selected()?.id"
                    (click)="open(entity.id)"
                    tabindex="0"
                    (keydown.enter)="open(entity.id)"
                    role="button"
                  >
                    <td>
                      <strong>{{ entity.entityValue }}</strong
                      ><span class="rule-id">{{ entity.entityType }}</span>
                    </td>
                    <td>
                      <span [class]="riskClass(entity.riskScore)">{{ entity.riskScore }}</span>
                    </td>
                    <td>{{ entity.failedLoginsHour }}</td>
                    <td>{{ entity.lastAnomaly || '—' }}</td>
                    <td class="nowrap">{{ entity.lastSeenAt | date: 'MMM d, HH:mm' : 'UTC' }}</td>
                  </tr>
                }
              </tbody>
            </table>
          </div>
        } @else if (!loading()) {
          <div class="empty-state">
            <h2>No entities tracked yet</h2>
            <p>
              UEBA builds baselines from ingested logs that carry a user. Forward authentication
              logs to populate it.
            </p>
          </div>
        }
      </section>
      @if (selected(); as e) {
        <section class="panel panel-padding">
          <button type="button" class="link-button panel-close" (click)="selected.set(null)">
            Close <span aria-hidden="true">&times;</span>
          </button>
          <h2 class="break-word">
            {{ e.entityValue }} <span class="muted small-text">({{ e.entityType }})</span>
          </h2>
          <dl class="triage-facts">
            <div>
              <dt>Risk score</dt>
              <dd>
                <span [class]="riskClass(e.riskScore)">{{ e.riskScore }}</span>
              </dd>
            </div>
            <div>
              <dt>Events observed</dt>
              <dd>{{ e.eventCount }}</dd>
            </div>
            <div>
              <dt>Failed logins (hr)</dt>
              <dd>{{ e.failedLoginsHour }}</dd>
            </div>
            <div>
              <dt>Known source IPs</dt>
              <dd>{{ e.knownSourceIpCount }}</dd>
            </div>
            <div>
              <dt>First seen</dt>
              <dd>{{ e.firstSeenAt | date: 'medium' }}</dd>
            </div>
            <div>
              <dt>Last anomaly</dt>
              <dd>
                {{ e.lastAnomaly || '—'
                }}{{ e.lastAnomalyAt ? ' · ' + (e.lastAnomalyAt | date: 'short') : '' }}
              </dd>
            </div>
          </dl>
          @if (e.knownSourceIps.length) {
            <h3>Known source IPs</h3>
            <p class="break-word">
              <code>{{ e.knownSourceIps.join(', ') }}</code>
            </p>
          }
          <h3>Recent UEBA alerts</h3>
          @if (e.recentAlerts.length) {
            <ul>
              @for (alert of e.recentAlerts; track alert.id) {
                <li>
                  <a [routerLink]="['/alerts', alert.id]">{{ alert.title }}</a>
                  <span class="muted small-text">
                    · {{ alert.severity }} · {{ alert.detectedAt | date: 'short' }}</span
                  >
                  @if (alert.incidentId) {
                    <a [routerLink]="['/incidents', alert.incidentId]"> → case</a>
                  }
                </li>
              }
            </ul>
          } @else {
            <p class="muted">No anomaly alerts for this entity.</p>
          }
        </section>
      }
    }
  `,
  styles: [
    `
      .log-stats {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
        gap: 12px;
        margin-bottom: 16px;
      }
      .log-stats .stat-card {
        padding: 14px 16px;
      }
      .log-stats strong {
        display: block;
        font-size: 24px;
      }
      .log-stats span {
        color: var(--muted);
        font-size: 12px;
      }
      .queue-table tbody tr {
        cursor: pointer;
      }
      .risk-high {
        background: #b91c1c !important;
        color: #fff !important;
      }
      .risk-med {
        background: #eaae26 !important;
        color: #29200a !important;
      }
      .risk-low {
        background: #5b6b7f !important;
        color: #fff !important;
      }
      .risk-high,
      .risk-med,
      .risk-low {
        border-radius: 2px;
        font-size: 12px;
        padding: 3px 8px;
        font-weight: 700;
      }
    `,
  ],
})
export class UebaPage {
  private readonly http = inject(HttpClient);
  private readonly destroy = inject(DestroyRef);
  protected readonly data = signal<EntityPage | null>(null);
  protected readonly selected = signal<EntityDetail | null>(null);
  protected readonly loading = signal(true);
  protected readonly errors = signal<string[]>([]);

  constructor() {
    this.load();
  }
  protected load(): void {
    this.loading.set(true);
    this.http
      .get<EntityPage>('/api/ueba/entities')
      .pipe(
        finalize(() => this.loading.set(false)),
        takeUntilDestroyed(this.destroy),
      )
      .subscribe({ next: (d) => this.data.set(d), error: (e) => this.errors.set(apiErrors(e)) });
  }
  protected open(id: number): void {
    if (this.selected()?.id === id) {
      this.selected.set(null);
      return;
    }
    this.http
      .get<EntityDetail>(`/api/ueba/entities/${id}`)
      .pipe(takeUntilDestroyed(this.destroy))
      .subscribe({
        next: (d) => this.selected.set(d),
        error: (e) => this.errors.set(apiErrors(e)),
      });
  }
  protected riskClass(score: number): string {
    return score >= 60 ? 'risk-high' : score >= 30 ? 'risk-med' : 'risk-low';
  }
}
