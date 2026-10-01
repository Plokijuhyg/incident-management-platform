import { DatePipe } from '@angular/common';
import { Component, inject } from '@angular/core';
import { toSignal } from '@angular/core/rxjs-interop';
import { ActivatedRoute, Router, RouterLink } from '@angular/router';
import { Subject, catchError, combineLatest, map, of, startWith, switchMap } from 'rxjs';
import { LoadState, Page } from '../../core/models/api';
import { ManagedUser, roleLabels } from '../../core/models/operations';
import { Users } from '../../core/services/users';
import { apiErrors } from '../../core/services/api-errors';
import { ErrorNotice } from '../../shared/components/error-notice';
@Component({
  imports: [RouterLink, DatePipe, ErrorNotice],
  template: ` <div class="page-heading">
      <div>
        <p class="eyebrow">ADMINISTRATION</p>
        <h1>Users</h1>
        <p class="muted">Manage accounts and access to the workspace.</p>
      </div>
      <a class="button" routerLink="/users/new">New user</a>
    </div>
    <section class="panel">
      <div class="panel-heading">
        <div>
          <h2>User directory</h2>
          <p class="muted small-text">Active and deactivated accounts</p>
        </div>
        <button class="button secondary small" [disabled]="state().loading" (click)="reload.next()">
          Refresh
        </button>
      </div>
      <app-error-notice [messages]="state().errors" />
      @if (state().errors.length) {
        <div class="panel-padding">
          <button class="button secondary" (click)="reload.next()">Try again</button>
        </div>
      }
      @if (state().loading) {
        <div class="empty-state" role="status">Loading users...</div>
      }
      @if (state().data; as page) {
        @if (page.items.length) {
          <div class="table-scroll">
            <table>
              <caption class="sr-only">
                User directory
              </caption>
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Roles</th>
                  <th>Account</th>
                  <th>Last login</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                @for (user of page.items; track user.id) {
                  <tr>
                    <td>
                      <a [routerLink]="['/users', user.id]"
                        ><strong>{{ user.fullName }}</strong></a
                      ><small>{{ user.email }}</small>
                    </td>
                    <td>{{ roleNames(user.roles) }}</td>
                    <td>
                      <span
                        class="badge"
                        [class.severity-0]="user.isActive"
                        [class.neutral]="!user.isActive"
                        >{{ user.isActive ? 'Active' : 'Deactivated' }}</span
                      >
                    </td>
                    <td>{{ user.lastLoginAt ? (user.lastLoginAt | date: 'medium') : 'Never' }}</td>
                    <td>
                      <a
                        [routerLink]="['/users', user.id]"
                        [attr.aria-label]="'Manage ' + user.fullName"
                        >Manage &rarr;</a
                      >
                    </td>
                  </tr>
                }
              </tbody>
            </table>
          </div>
        } @else {
          <div class="empty-state">
            <h2>No users on this page</h2>
            @if (page.page > 1) {
              <button class="button secondary" (click)="go(1)">First page</button>
            }
          </div>
        }
        <footer class="pagination">
          <span
            >{{ page.totalCount }} users &middot; Page {{ page.page }} of
            {{ page.totalPages || 1 }}</span
          >
          <div>
            <button
              class="button secondary small"
              [disabled]="!page.hasPreviousPage"
              (click)="go(page.page - 1)"
            >
              Previous</button
            ><button
              class="button secondary small"
              [disabled]="!page.hasNextPage"
              (click)="go(page.page + 1)"
            >
              Next
            </button>
          </div>
        </footer>
      }
    </section>`,
})
export class UserList {
  private readonly route = inject(ActivatedRoute);
  private readonly router = inject(Router);
  private readonly users = inject(Users);
  protected readonly reload = new Subject<void>();
  protected readonly state = toSignal(
    combineLatest([this.route.queryParamMap, this.reload.pipe(startWith(undefined))]).pipe(
      switchMap(([params]) => {
        const value = Number(params.get('page') ?? 1);
        const page = Number.isSafeInteger(value) && value > 0 && value <= 1000000 ? value : 1;
        return this.users.list(page).pipe(
          map((data) => ({ loading: false, data, errors: [] }) as LoadState<Page<ManagedUser>>),
          catchError((e) => of({ loading: false, data: null, errors: apiErrors(e) })),
          startWith({ loading: true, data: null, errors: [] }),
        );
      }),
    ),
    { initialValue: { loading: true, data: null, errors: [] } as LoadState<Page<ManagedUser>> },
  );
  protected roleNames(roles: string[]): string {
    return roles.map((role) => roleLabels[role] ?? role).join(', ');
  }
  protected go(page: number): void {
    void this.router.navigate([], { relativeTo: this.route, queryParams: { page } });
  }
}
