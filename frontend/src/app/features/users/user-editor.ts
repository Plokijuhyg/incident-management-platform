import { DatePipe } from '@angular/common';
import {
  Component,
  DestroyRef,
  OnChanges,
  SimpleChanges,
  inject,
  input,
  output,
  signal,
} from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { FormBuilder, ReactiveFormsModule, Validators } from '@angular/forms';
import { Observable, finalize } from 'rxjs';
import { ManagedUser, Role } from '../../core/models/operations';
import { Users } from '../../core/services/users';
import { Auth } from '../../core/services/auth';
import { apiErrors } from '../../core/services/api-errors';
import { ErrorNotice } from '../../shared/components/error-notice';
import { RolePicker } from './role-picker';
@Component({
  selector: 'app-user-editor',
  imports: [ReactiveFormsModule, ErrorNotice, RolePicker, DatePipe],
  template: ` <app-error-notice [messages]="errors()" />
    @if (success()) {
      <p class="success-notice" role="status">{{ success() }}</p>
    }
    <div class="create-grid">
      <div>
        <form
          class="panel panel-padding"
          [formGroup]="profile"
          (ngSubmit)="saveProfile()"
          novalidate
        >
          <fieldset [disabled]="busy()">
            <legend>{{ user() ? 'Profile' : 'New account' }}</legend>
            <label for="user-name">Full name</label
            ><input id="user-name" formControlName="fullName" maxlength="150" autocomplete="name" />
            @if (profile.controls.fullName.touched && profile.controls.fullName.invalid) {
              <p class="field-error">Enter a full name (up to 150 characters).</p>
            }
            <label for="job-title">Job title (optional)</label
            ><input id="job-title" formControlName="jobTitle" maxlength="100" />
            @if (!user()) {
              <label for="user-email">Email address</label
              ><input
                id="user-email"
                type="email"
                formControlName="email"
                maxlength="256"
                autocomplete="off"
              />
              @if (profile.controls.email.touched && profile.controls.email.invalid) {
                <p class="field-error">Enter a valid email address (up to 256 characters).</p>
              }
              <label for="new-password">Initial password</label
              ><input
                id="new-password"
                type="password"
                formControlName="password"
                autocomplete="new-password"
                aria-describedby="password-rules"
              /><small id="password-rules"
                >At least 8 characters, with an uppercase letter, a lowercase letter, and a
                digit.</small
              >
              @if (profile.controls.password.touched && profile.controls.password.invalid) {
                <p class="field-error">The password must meet all requirements above.</p>
              }
              <h3 class="section-space">Roles</h3>
              <app-role-picker
                [roles]="roles()"
                [selected]="roleForm.controls.roles.value"
                [disabled]="busy()"
                (selectionChange)="setRoles($event)"
              />
              @if (roleForm.touched && roleForm.invalid) {
                <p class="field-error">Select at least one role.</p>
              }
            }
          </fieldset>
          <div class="form-actions">
            <button class="button" [disabled]="busy() || (!user() && !roles().length)">
              {{ busy() ? 'Saving...' : user() ? 'Save profile' : 'Create user' }}
            </button>
          </div>
        </form>
        @if (user(); as person) {
          <form class="panel panel-padding" [formGroup]="roleForm" (ngSubmit)="saveRoles()">
            <fieldset [disabled]="busy()">
              <legend>Role assignments</legend>
              <app-role-picker
                [roles]="roles()"
                [selected]="roleForm.controls.roles.value"
                [disabled]="busy()"
                [locked]="person.id === auth.user()?.id ? ['ADMIN'] : []"
                (selectionChange)="setRoles($event)"
              />
              @if (person.id === auth.user()?.id) {
                <p class="muted small-text">Your own Administrator role must remain assigned.</p>
              }
              @if (roleForm.touched && roleForm.invalid) {
                <p class="field-error">Select at least one role.</p>
              }
            </fieldset>
            <div class="form-actions">
              <button class="button" [disabled]="busy()">Save roles</button>
            </div>
          </form>
        }
      </div>
      <aside class="creation-notes">
        @if (user(); as person) {
          <h2>Account information</h2>
          <p>Sign in with the email below and the password you set. Role names are permissions, not separate login accounts.</p>
          @if(person.isActive){
            <form [formGroup]="passwordReset" (ngSubmit)="resetPassword()"><label for="reset-user-password">Set a new password</label><input id="reset-user-password" type="password" formControlName="password" autocomplete="new-password" maxlength="128" /><small>8-128 characters with uppercase, lowercase and a digit. Existing sessions will end.</small><button class="button secondary" [disabled]="busy() || passwordReset.invalid">Reset password</button></form>
          }
          <dl>
            <dt>Email</dt>
            <dd>{{ person.email }}</dd>
            <dt>Status</dt>
            <dd>{{ person.isActive ? 'Active' : 'Deactivated' }}</dd>
            <dt>Created</dt>
            <dd>{{ person.createdAt | date: 'medium' }}</dd>
            <dt>Last login</dt>
            <dd>{{ person.lastLoginAt ? (person.lastLoginAt | date: 'medium') : 'Never' }}</dd>
          </dl>
          @if (person.isActive && person.id !== auth.user()?.id) {
            <hr />
            <h3>Deactivate account</h3>
            <p>Prevents sign-in and ends active sessions. Historical records are retained.</p>
            @if (confirmDeactivate()) {
              <div class="confirm-box" role="group" aria-label="Confirm account deactivation">
                <p>
                  Deactivate <strong>{{ person.fullName }}</strong
                  >?
                </p>
                <div class="button-row">
                  <button class="button danger" [disabled]="busy()" (click)="deactivate()">
                    Confirm deactivation</button
                  ><button
                    class="button secondary"
                    [disabled]="busy()"
                    (click)="confirmDeactivate.set(false)"
                  >
                    Cancel
                  </button>
                </div>
              </div>
            } @else {
              <button
                class="button danger-outline"
                [disabled]="busy()"
                (click)="confirmDeactivate.set(true)"
              >
                Deactivate user
              </button>
            }
          }
          @if (person.id === auth.user()?.id) {
            <p class="notice">You cannot deactivate your own account.</p>
          }
        } @else {
          <h2>Give the right access</h2>
          <p>
            SOC analysts work on assigned incidents. Security managers coordinate response.
            Administrators also manage users and roles.
          </p>
          <p>Create an individual account for each team member.</p>
        }
      </aside>
    </div>`,
})
export class UserEditor implements OnChanges {
  readonly user = input<ManagedUser | null>(null);
  readonly roles = input.required<Role[]>();
  readonly saved = output<ManagedUser>();
  protected readonly auth = inject(Auth);
  private readonly api = inject(Users);
  private readonly fb = inject(FormBuilder);
  private readonly destroyRef = inject(DestroyRef);
  protected readonly busy = signal(false);
  protected readonly passwordReset=this.fb.nonNullable.group({password:['',[Validators.required,Validators.minLength(8),Validators.maxLength(128),Validators.pattern(/[A-Z]/),Validators.pattern(/[a-z]/),Validators.pattern(/[0-9]/)]]});
  protected resetPassword(){const person=this.user();if(!person||this.busy()||this.passwordReset.invalid)return;this.busy.set(true);this.errors.set([]);
    this.api.resetPassword(person.id,this.passwordReset.getRawValue().password).pipe(takeUntilDestroyed(this.destroyRef),finalize(()=>this.busy.set(false))).subscribe({next:()=>{this.passwordReset.reset();this.success.set('Password updated. Sign in with '+person.email+' and the new password.');},error:e=>this.errors.set(apiErrors(e))});}
  protected readonly errors = signal<string[]>([]);
  protected readonly success = signal('');
  protected readonly confirmDeactivate = signal(false);
  protected readonly profile = this.fb.nonNullable.group({
    fullName: ['', [Validators.required, Validators.maxLength(150), Validators.pattern(/\S/)]],
    jobTitle: ['', Validators.maxLength(100)],
    email: [''],
    password: [''],
  });
  protected readonly roleForm = this.fb.nonNullable.group({
    roles: this.fb.nonNullable.control<string[]>(['SOC_ANALYST'], Validators.required),
  });
  ngOnChanges(changes: SimpleChanges): void {
    const user = this.user();
    const changedAccount = changes['user']?.previousValue?.id !== user?.id;
    if(changedAccount)this.passwordReset.reset();
    if (changedAccount || !this.profile.dirty)
      this.profile.reset({
        fullName: user?.fullName ?? '',
        jobTitle: user?.jobTitle ?? '',
        email: '',
        password: '',
      });
    if (changedAccount || !this.roleForm.dirty)
      this.roleForm.reset({ roles: [...(user?.roles ?? ['SOC_ANALYST'])] });
    this.profile.controls.email.setValidators(
      user ? [] : [Validators.required, Validators.email, Validators.maxLength(256)],
    );
    this.profile.controls.password.setValidators(
      user
        ? []
        : [
            Validators.required,
            Validators.minLength(8),
            Validators.pattern(/[A-Z]/),
            Validators.pattern(/[a-z]/),
            Validators.pattern(/[0-9]/),
          ],
    );
    this.profile.controls.email.updateValueAndValidity();
    this.profile.controls.password.updateValueAndValidity();
    this.confirmDeactivate.set(false);
  }
  protected setRoles(roles: string[]): void {
    this.roleForm.controls.roles.setValue(roles);
    this.roleForm.markAsTouched();
    this.roleForm.markAsDirty();
  }
  private run(
    request: Observable<ManagedUser>,
    message: string,
    section: 'profile' | 'roles' = 'profile',
  ): void {
    if (this.busy()) return;
    this.busy.set(true);
    this.errors.set([]);
    this.success.set('');
    request
      .pipe(
        takeUntilDestroyed(this.destroyRef),
        finalize(() => this.busy.set(false)),
      )
      .subscribe({
        next: (user) => {
          this.profile.controls.password.reset();
          (section === 'profile' ? this.profile : this.roleForm).markAsPristine();
          if (user.id === this.auth.user()?.id)
            this.auth.user.set({
              id: user.id,
              email: user.email,
              fullName: user.fullName,
              roles: user.roles,
            });
          this.saved.emit(user);
          this.success.set(message);
        },
        error: (e) => this.errors.set(apiErrors(e)),
      });
  }
  protected saveProfile(): void {
    this.profile.markAllAsTouched();
    this.roleForm.markAllAsTouched();
    if (
      !this.auth.hasRole('ADMIN') ||
      this.profile.invalid ||
      (!this.user() && this.roleForm.invalid)
    )
      return;
    const value = this.profile.getRawValue();
    const person = this.user();
    this.run(
      person
        ? this.api.update(person.id, {
            fullName: value.fullName.trim(),
            jobTitle: value.jobTitle.trim() || null,
          })
        : this.api.create({
            ...value,
            fullName: value.fullName.trim(),
            email: value.email.trim(),
            jobTitle: value.jobTitle.trim() || null,
            roles: this.roleForm.getRawValue().roles,
          }),
      person ? 'Profile updated.' : 'User created.',
    );
  }
  protected saveRoles(): void {
    this.roleForm.markAllAsTouched();
    const person = this.user();
    const roles = this.roleForm.getRawValue().roles;
    if (
      !person ||
      !this.auth.hasRole('ADMIN') ||
      this.roleForm.invalid ||
      (person.id === this.auth.user()?.id && !roles.includes('ADMIN'))
    )
      return;
    this.run(this.api.replaceRoles(person.id, roles), 'Roles updated.', 'roles');
  }
  protected deactivate(): void {
    const person = this.user();
    if (
      !person ||
      !this.confirmDeactivate() ||
      this.busy() ||
      !this.auth.hasRole('ADMIN') ||
      person.id === this.auth.user()?.id
    )
      return;
    this.busy.set(true);
    this.errors.set([]);
    this.success.set('');
    this.api
      .deactivate(person.id)
      .pipe(
        takeUntilDestroyed(this.destroyRef),
        finalize(() => this.busy.set(false)),
      )
      .subscribe({
        next: () => {
          this.saved.emit({ ...person, isActive: false });
          this.confirmDeactivate.set(false);
          this.success.set('Account deactivated.');
        },
        error: (e) => this.errors.set(apiErrors(e)),
      });
  }
}
