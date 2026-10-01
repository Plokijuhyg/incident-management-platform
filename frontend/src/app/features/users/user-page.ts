import { Component, inject } from '@angular/core';
import { toSignal } from '@angular/core/rxjs-interop';
import { ActivatedRoute, Router, RouterLink } from '@angular/router';
import {
  Subject,
  catchError,
  combineLatest,
  forkJoin,
  map,
  merge,
  of,
  startWith,
  switchMap,
} from 'rxjs';
import { LoadState } from '../../core/models/api';
import { ManagedUser, Role } from '../../core/models/operations';
import { Users } from '../../core/services/users';
import { apiErrors } from '../../core/services/api-errors';
import { ErrorNotice } from '../../shared/components/error-notice';
import { UserEditor } from './user-editor';
type UserData = { user: ManagedUser | null; roles: Role[] };
@Component({
  imports: [RouterLink, ErrorNotice, UserEditor],
  template: `<a class="back-link" routerLink="/users">&larr; All users</a>
    <div class="page-heading">
      <div>
        <p class="eyebrow">ADMINISTRATION</p>
        <h1>{{ state().data?.user ? 'Manage user' : 'User account' }}</h1>
      </div>
    </div>
    <app-error-notice [messages]="state().errors" />
    @if (state().loading) {
      <div role="status" class="empty-state">Loading account...</div>
    }
    @if (state().errors.length) {
      <button class="button secondary" (click)="reload.next()">Try again</button>
    }
    @if (state().data; as data) {
      <app-user-editor [user]="data.user" [roles]="data.roles" (saved)="saved($event)" />
    }`,
})
export class UserPage {
  private readonly route = inject(ActivatedRoute);
  private readonly router = inject(Router);
  private readonly api = inject(Users);
  protected readonly reload = new Subject<void>();
  private readonly updates = new Subject<UserData>();
  protected readonly state = toSignal(
    combineLatest([this.route.paramMap, this.reload.pipe(startWith(undefined))]).pipe(
      switchMap(([params]) => {
        const raw = params.get('id');
        const id = Number(raw);
        if (raw && (!Number.isSafeInteger(id) || id < 1 || id > 2147483647))
          return of({ loading: false, data: null, errors: ['This user could not be found.'] });
        return merge(
          forkJoin({ user: raw ? this.api.detail(id) : of(null), roles: this.api.roles() }).pipe(
            map((data) => ({ loading: false, data, errors: [] }) as LoadState<UserData>),
            catchError((e) => of({ loading: false, data: null, errors: apiErrors(e) })),
            startWith({ loading: true, data: null, errors: [] }),
          ),
          this.updates.pipe(map((data) => ({ loading: false, data, errors: [] }))),
        );
      }),
    ),
    { initialValue: { loading: true, data: null, errors: [] } as LoadState<UserData> },
  );
  protected saved(user: ManagedUser): void {
    const data = this.state().data;
    if (!data) return;
    if (!data.user) {
      void this.router.navigate(['/users', user.id]);
      return;
    }
    this.updates.next({ user, roles: data.roles });
  }
}
