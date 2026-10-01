import { IntelPanel } from '../../shared/components/intel-panel';
import { EntityAudit } from '../../shared/components/entity-audit';
import { Auth } from '../../core/services/auth';
import { InvestigationPanel } from './investigation-panel';
import { IncidentActions } from './incident-actions';
import { EvidencePanel } from '../evidence/evidence-panel';
import { DatePipe } from '@angular/common';
import { Component, inject, signal } from '@angular/core';
import { toSignal } from '@angular/core/rxjs-interop';
import { ActivatedRoute, RouterLink } from '@angular/router';
import { Subject, merge, catchError, combineLatest, map, of, startWith, switchMap } from 'rxjs';
import {
  IncidentDetail,
  LoadState,
  categories,
  priorities,
  sources,
  statuses,
} from '../../core/models/api';
import { Incidents } from '../../core/services/incidents';
import { apiErrors } from '../../core/services/api-errors';
import { ErrorNotice } from '../../shared/components/error-notice';
import { SeverityBadge } from '../../shared/components/severity-badge';
@Component({
  imports: [
    RouterLink,
    DatePipe,
    ErrorNotice,
    SeverityBadge,
    IncidentActions,
    EvidencePanel,
    InvestigationPanel,
    EntityAudit,
    IntelPanel,
  ],
  template: ` <a class="back-link" routerLink="/incidents">&larr; All incidents</a>
    @if (state().loading) {
      <div class="empty-state" role="status">Loading incident...</div>
    }
    <app-error-notice [messages]="state().errors" />
    @if (state().errors.length) {
      <button class="button secondary" (click)="reload.next()">Try again</button>
    }
    @if (state().data; as incident) {
      <div class="page-heading">
        <div>
          <p class="eyebrow">{{ incident.incidentNumber }}</p>
          <h1 class="break-word">{{ incident.title }}</h1>
          <p class="muted">
            Reported by {{ incident.createdByName }} <span class="divider">&middot;</span>
            {{ incident.createdAt | date: 'medium' }}
          </p>
        </div>
        <app-severity [value]="incident.severity" />
      </div>
      <app-intel-panel kind="incidents" [recordId]="incident.id" (enriched)="reload.next()" />
      @if (incident.recommendedActions?.length) {
        <section class="panel panel-padding">
          <h2>Recommended response</h2>
          <p class="notice">Suggestion only. Human review is required; no action has been executed.</p>
          @for (action of incident.recommendedActions; track action.alertId) {
            <p>{{ action.text }}</p>
            <small>Source alert #{{ action.alertId }} &middot; {{ action.ruleId }}</small>
          }
        </section>
      }
      <app-incident-actions [incident]="incident" (updated)="updates.next($event)" />
      <div class="detail-grid">
        <div>
          <section class="panel panel-padding">
            <h2>Incident overview</h2>
            <p class="description">{{ incident.description }}</p>
            @if (incident.resolutionSummary) {
              <hr />
              <h2>Resolution summary</h2>
              <p class="description">{{ incident.resolutionSummary }}</p>
            }
          </section>
          <section class="panel panel-padding">
            <h2>Response milestones</h2>
            <p class="muted">
              Recorded milestones for this incident. Times are shown in your local timezone.
            </p>
            <ol class="milestones">
              @for (milestone of milestones(incident); track milestone.label) {
                <li [class.recorded]="milestone.time">
                  <span class="milestone-dot" aria-hidden="true"></span
                  ><strong>{{ milestone.label }}</strong
                  ><span>{{
                    milestone.time ? (milestone.time | date: 'medium') : 'Not recorded'
                  }}</span>
                </li>
              }
            </ol>
          </section>
        </div>
        <aside class="panel panel-padding detail-meta">
          <h2>Incident details</h2>
          <dl>
            <dt>Status</dt>
            <dd>
              <span class="badge neutral">{{ statuses.at(incident.status) ?? 'Unknown' }}</span>
            </dd>
            <dt>Priority</dt>
            <dd>{{ priorities.at(incident.priority) ?? 'Unknown' }}</dd>
            <dt>Category</dt>
            <dd>{{ categories.at(incident.category) ?? 'Unknown' }}</dd>
            <dt>Source</dt>
            <dd>{{ sources.at(incident.source) ?? 'Unknown' }}</dd>
            <dt>Assigned to</dt>
            <dd>{{ incident.assignedToName || 'Unassigned' }}</dd>
            <dt>Last updated</dt>
            <dd>{{ incident.updatedAt | date: 'medium' }}</dd>
          </dl>
        </aside>
      </div>
      <section class="panel panel-padding">
        <h2>Continue the investigation</h2>
        <p class="muted">
          Discussion, timeline, response actions and linked intelligence in one workspace.
        </p>
        <button class="button secondary" (click)="showWorkspace.set(!showWorkspace())">
          {{ showWorkspace() ? 'Hide investigation workspace' : 'Open investigation workspace' }}
        </button>
      </section>
      @if (showWorkspace()) {
        <app-investigation [incidentId]="incident.id" />
      }
      @if (auth.canManageIncidents()) {
        <section class="panel panel-padding">
          <button class="button secondary" (click)="showAudit.set(!showAudit())">
            {{ showAudit() ? 'Hide audit history' : 'Open audit history' }}
          </button>
        </section>
        @if (showAudit()) {
          <app-entity-audit [incidentId]="incident.id" />
        }
      }
      <app-evidence [incidentId]="incident.id" />
    }`,
})
export class IncidentDetailPage {
  protected auth = inject(Auth);
  protected showAudit = signal(false);
  protected readonly showWorkspace = signal(false);
  private readonly route = inject(ActivatedRoute);
  private readonly incidents = inject(Incidents);
  protected readonly reload = new Subject<void>();
  protected readonly updates = new Subject<IncidentDetail>();
  protected readonly statuses = statuses;
  protected readonly priorities = priorities;
  protected readonly categories = categories;
  protected readonly sources = sources;
  protected readonly state = toSignal(
    combineLatest([this.route.paramMap, this.reload.pipe(startWith(undefined))]).pipe(
      switchMap(([params]) => {
        const id = Number(params.get('id'));
        if (!Number.isSafeInteger(id) || id < 1 || id > 2147483647)
          return of({ loading: false, data: null, errors: ['This incident could not be found.'] });
        return merge(
          this.incidents.detail(id).pipe(
            map((data) => ({ loading: false, data, errors: [] }) as LoadState<IncidentDetail>),
            catchError((error) => of({ loading: false, data: null, errors: apiErrors(error) })),
            startWith({ loading: true, data: null, errors: [] }),
          ),
          this.updates.pipe(
            map((data) => ({ loading: false, data, errors: [] }) as LoadState<IncidentDetail>),
          ),
        );
      }),
    ),
    { initialValue: { loading: true, data: null, errors: [] } as LoadState<IncidentDetail> },
  );
  protected milestones(i: IncidentDetail) {
    return [
      { label: 'Occurred', time: i.occurredAt },
      { label: 'Detected', time: i.detectedAt },
      { label: 'Created', time: i.createdAt },
      { label: 'Triaged', time: i.triagedAt },
      { label: 'Contained', time: i.containedAt },
      { label: 'Resolved', time: i.resolvedAt },
      { label: 'Closed', time: i.closedAt },
    ];
  }
}
