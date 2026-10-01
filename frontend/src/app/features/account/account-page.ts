import { Component, DestroyRef, inject, signal } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Router } from '@angular/router';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { finalize } from 'rxjs';
import { Auth } from '../../core/services/auth';
import { apiErrors } from '../../core/services/api-errors';
import { DataForm, Field } from '../../shared/components/data-form';
import { ErrorNotice } from '../../shared/components/error-notice';
@Component({
  imports: [DataForm, ErrorNotice],
  template: `<div class="page-heading">
      <div>
        <p class="eyebrow">PERSONAL WORKSPACE</p>
        <h1>Your account</h1>
        <p class="muted">Manage your sign-in security.</p>
      </div>
    </div>
    <div class="create-grid">
      <section class="panel panel-padding">
        <h2>Change password</h2>
        <p class="muted">
          Use at least 8 characters with an uppercase letter, a lowercase letter and a digit.
        </p>
        <app-error-notice [messages]="errors()" /><app-data-form
          [fields]="fields"
          [busy]="busy()"
          label="Change password"
          (saved)="change($event)"
        />
      </section>
      <aside class="creation-notes">
        <div class="avatar large">{{ auth.user()?.fullName?.slice(0, 1) }}</div>
        <h2>{{ auth.user()?.fullName }}</h2>
        <p>{{ auth.user()?.email }}</p>
        <p>{{ auth.user()?.roles?.join(', ') }}</p>
        <p class="notice">After changing your password, sign in again with the new password.</p>
      </aside>
    </div>`,
})
export class AccountPage {
  protected auth = inject(Auth);
  private http = inject(HttpClient);
  private router = inject(Router);
  private destroy = inject(DestroyRef);
  protected errors = signal<string[]>([]);
  protected busy = signal(false);
  protected fields: Field[] = [
    { key: 'currentPassword', label: 'Current password', type: 'password', required: true },
    { key: 'newPassword', label: 'New password', type: 'password', required: true },
    { key: 'confirmPassword', label: 'Confirm new password', type: 'password', required: true },
  ];
  protected change(value: Record<string, unknown>) {
    if (this.busy()) return;
    const password = String(value['newPassword']);
    if (password !== value['confirmPassword']) {
      this.errors.set(['New passwords do not match.']);
      return;
    }
    if (
      password.length < 8 ||
      !/[A-Z]/.test(password) ||
      !/[a-z]/.test(password) ||
      !/[0-9]/.test(password)
    ) {
      this.errors.set(['The new password does not meet the requirements.']);
      return;
    }
    this.busy.set(true);
    this.http
      .post('/api/auth/change-password', {
        currentPassword: value['currentPassword'],
        newPassword: password,
      })
      .pipe(
        takeUntilDestroyed(this.destroy),
        finalize(() => this.busy.set(false)),
      )
      .subscribe({
        next: () => {
          this.auth.clear();
          void this.router.navigate(['/login']);
        },
        error: (e) => this.errors.set(apiErrors(e)),
      });
  }
}
