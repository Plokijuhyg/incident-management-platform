import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { HttpErrorResponse } from '@angular/common/http';
import { Component, DestroyRef, inject, signal } from '@angular/core';
import { FormBuilder, ReactiveFormsModule, Validators } from '@angular/forms';
import { ActivatedRoute, Router } from '@angular/router';
import { finalize } from 'rxjs';
import { Auth, safeReturnUrl } from '../../core/services/auth';
import { apiErrors } from '../../core/services/api-errors';
import { ErrorNotice } from '../../shared/components/error-notice';
@Component({
  imports: [ReactiveFormsModule, ErrorNotice],
  template: ` <div class="login-layout">
    <section class="login-story">
      <div class="brand"><span class="brand-mark">IP</span> Incident Platform</div>
      <div>
        <p class="eyebrow">SECURITY OPERATIONS</p>
        <h1>Clarity when<br />every minute counts.</h1>
        <p>
          One workspace to investigate incidents,<br />coordinate your response, and keep the
          record.
        </p>
      </div>
      <small>INCIDENT RESPONSE WORKSPACE</small>
    </section>
    <main class="login-main">
      <section class="login-card">
        <p class="eyebrow">WELCOME BACK</p>
        <h2>Sign in to your workspace</h2>
        <p class="muted">Use the account provided by your administrator.</p>
        @if (expired) {
          <p class="notice" role="status">Your session has ended. Sign in to continue.</p>
        }
        <app-error-notice [messages]="errors()" />
        <form [formGroup]="form" (ngSubmit)="submit()" novalidate>
          <label for="email">Email address</label
          ><input
            id="email"
            type="email"
            formControlName="email"
            autocomplete="username"
            placeholder="you@company.com"
            [attr.aria-invalid]="form.controls.email.touched && form.controls.email.invalid"
            aria-describedby="email-error"
          />
          @if (form.controls.email.touched && form.controls.email.invalid) {
            <small class="field-error" id="email-error">Enter a valid email address.</small>
          }
          <label for="password">Password</label
          ><input
            id="password"
            type="password"
            formControlName="password"
            autocomplete="current-password"
            [attr.aria-invalid]="form.controls.password.touched && form.controls.password.invalid"
            aria-describedby="password-error"
          />
          @if (form.controls.password.touched && form.controls.password.invalid) {
            <small class="field-error" id="password-error">Enter your password.</small>
          }
          <button class="button full" type="submit" [disabled]="busy()">
            {{ busy() ? 'Signing in...' : 'Sign in' }} <span aria-hidden="true">&rarr;</span>
          </button>
        </form>
        <p class="login-help">Need access? Contact your administrator.</p>
      </section>
    </main>
  </div>`,
})
export class Login {
  private readonly destroyRef = inject(DestroyRef);
  private readonly auth = inject(Auth);
  private readonly router = inject(Router);
  private readonly route = inject(ActivatedRoute);
  protected readonly expired = this.route.snapshot.queryParamMap.has('expired');
  protected readonly form = inject(FormBuilder).nonNullable.group({
    email: ['', [Validators.required, Validators.email]],
    password: ['', Validators.required],
  });
  protected readonly busy = signal(false);
  protected readonly errors = signal<string[]>([]);
  protected submit(): void {
    this.form.markAllAsTouched();
    if (this.form.invalid || this.busy()) return;
    this.busy.set(true);
    this.errors.set([]);
    const { email, password } = this.form.getRawValue();
    this.auth
      .login(email, password)
      .pipe(
        takeUntilDestroyed(this.destroyRef),
        finalize(() => this.busy.set(false)),
      )
      .subscribe({
        next: () =>
          void this.router.navigateByUrl(
            safeReturnUrl(this.route.snapshot.queryParamMap.get('returnUrl')),
          ),
        error: (e) =>
          this.errors.set(
            e instanceof HttpErrorResponse && e.status === 401
              ? ['Sign-in failed. Check your email and password, or contact your administrator.']
              : apiErrors(e),
          ),
      });
  }
}
