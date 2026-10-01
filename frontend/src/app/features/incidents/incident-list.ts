import { DatePipe } from '@angular/common';
import { Component, inject } from '@angular/core';
import { toSignal } from '@angular/core/rxjs-interop';
import { ActivatedRoute, Router, RouterLink } from '@angular/router';
import { Subject, catchError, combineLatest, map, of, startWith, switchMap } from 'rxjs';
import { IncidentSummary, LoadState, Page, categories, statuses } from '../../core/models/api';
import { Incidents } from '../../core/services/incidents';
import { apiErrors } from '../../core/services/api-errors';
import { ErrorNotice } from '../../shared/components/error-notice';
import { SeverityBadge } from '../../shared/components/severity-badge';

export function pageNumber(value: string | null): number {
  const page = Number(value ?? 1);
  return Number.isSafeInteger(page) && page > 0 && page <= 1_000_000 ? page : 1;
}
@Component({
  imports: [DatePipe, RouterLink, ErrorNotice, SeverityBadge],
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
          <p class="muted small-text">Most recently created first</p>
        </div>
        <button class="button secondary small" (click)="reload.next()" [disabled]="state().loading">
          Refresh
        </button>
      </div>
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
                  <th scope="col">Incident</th>
                  <th scope="col">Severity</th>
                  <th scope="col">Status</th>
                  <th scope="col">Category</th>
                  <th scope="col">Assignee</th>
                  <th scope="col">Created</th>
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
                    <td>{{ categories.at(incident.category) ?? 'Unknown' }}</td>
                    <td>{{ incident.assignedToName || 'Unassigned' }}</td>
                    <td class="nowrap">{{ incident.createdAt | date: 'MMM d, y, HH:mm' }}</td>
                  </tr>
                }
              </tbody>
            </table>
          </div>
        } @else {
          <div class="empty-state">
            <span class="empty-icon" aria-hidden="true">&#9636;</span>
            <h2>{{ page.totalCount ? 'No incidents on this page' : 'No incidents yet' }}</h2>
            <p>
              {{
                page.totalCount
                  ? 'Go back to the first page to view the incident register.'
                  : 'Create your first incident to start tracking a response.'
              }}
            </p>
            @if (page.totalCount) {
              <button class="button secondary" (click)="go(1)">First page</button>
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
  protected readonly reload = new Subject<void>();
  protected readonly categories = categories;
  protected readonly statuses = statuses;
  protected readonly state = toSignal(
    combineLatest([this.route.queryParamMap, this.reload.pipe(startWith(undefined))]).pipe(
      switchMap(([params]) =>
        this.incidents.list(pageNumber(params.get('page'))).pipe(
          map((data) => ({ loading: false, data, errors: [] }) as LoadState<Page<IncidentSummary>>),
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
}
