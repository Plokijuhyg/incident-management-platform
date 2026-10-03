import { HttpErrorResponse } from '@angular/common/http';
import {
  Component,
  DestroyRef,
  OnChanges,
  computed,
  inject,
  input,
  output,
  signal,
} from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { FormBuilder, ReactiveFormsModule, Validators } from '@angular/forms';
import { Observable, finalize } from 'rxjs';
import {
  IncidentDetail,
  categories,
  priorities,
  severities,
  statuses,
} from '../../core/models/api';
import { Assignee } from '../../core/models/operations';
import { Auth } from '../../core/services/auth';
import { Incidents } from '../../core/services/incidents';
import { Users } from '../../core/services/users';
import { apiErrors } from '../../core/services/api-errors';
import { ErrorNotice } from '../../shared/components/error-notice';
@Component({
  selector: 'app-incident-actions',
  imports: [ReactiveFormsModule, ErrorNotice],
  template: ` <section class="panel panel-padding" aria-label="Incident actions">
    <div class="action-toolbar">
      <h2>Response actions</h2>
      <div class="button-row">
        @if (canEdit()) {
          <button class="button secondary small" [disabled]="busy()" (click)="open('edit')">
            Edit incident</button
          ><button class="button secondary small" [disabled]="busy()" (click)="open('status')">
            Change status
          </button>
        }
        @if (canManage()) {
          <button class="button secondary small" [disabled]="busy()" (click)="open('assign')">
            Assign owner
          </button>
          @if (incident().status !== 7) {
            <button class="button secondary small" [disabled]="busy()" (click)="open('escalate')">
              Escalate (Tier {{ incident().tier }})
            </button>
            <button class="button secondary small" [disabled]="busy()" (click)="open('close')">
              Close incident
            </button>
          }
        }
      </div>
    </div>
    @if (!canEdit()) {
      <p class="muted small-text">
        Only the assigned analyst, a manager, or an administrator can edit this incident.
      </p>
    }
    @if (success()) {
      <p class="success-notice" role="status">{{ success() }}</p>
    }
    <app-error-notice [messages]="errors()" />
    @if (conflict()) {
      <div class="notice">
        <p>
          This record changed while you were editing. Your draft is preserved. Load the latest
          record before making your changes again.
        </p>
        <button class="button secondary" [disabled]="busy()" (click)="loadLatest()">
          Load latest (discard draft)
        </button>
      </div>
    }
    @if (mode() === 'edit') {
      <form [formGroup]="editForm" (ngSubmit)="saveEdit()" novalidate>
        <fieldset [disabled]="busy() || conflict()">
          <legend>Edit incident</legend>
          <label for="edit-title">Title</label
          ><input id="edit-title" formControlName="title" maxlength="200" />
          <label for="edit-description">Description</label
          ><textarea id="edit-description" formControlName="description" rows="5"></textarea>
          <div class="form-grid">
            <div>
              <label for="edit-severity">Severity</label
              ><select id="edit-severity" formControlName="severity">
                @for (label of severities; track $index) {
                  <option [ngValue]="$index">{{ label }}</option>
                }
              </select>
            </div>
            <div>
              <label for="edit-priority">Priority</label
              ><select id="edit-priority" formControlName="priority">
                @for (label of priorities; track $index) {
                  <option [ngValue]="$index">{{ label }}</option>
                }
              </select>
            </div>
            <div>
              <label for="edit-category">Category</label
              ><select id="edit-category" formControlName="category">
                @for (label of categories; track $index) {
                  <option [ngValue]="$index">{{ label }}</option>
                }
              </select>
            </div>
          </div>
          @if (editForm.touched && editForm.invalid) {
            <p class="field-error" role="alert">
              A title (up to 200 characters) and description are required.
            </p>
          }
        </fieldset>
        <div class="form-actions">
          <button type="button" class="button secondary" [disabled]="busy()" (click)="cancel()">
            Cancel</button
          ><button class="button" [disabled]="busy() || conflict()">
            {{ busy() ? 'Saving...' : 'Save changes' }}
          </button>
        </div>
      </form>
    }
    @if (mode() === 'status') {
      <form [formGroup]="statusForm" (ngSubmit)="saveStatus()">
        <fieldset [disabled]="busy()">
          <legend>Change status</legend>
          <label for="incident-status">New status</label
          ><select id="incident-status" formControlName="status">
            @for (option of statusOptions; track option.value) {
              <option [ngValue]="option.value">{{ option.label }}</option>
            }</select
          ><label for="status-note">Timeline note (optional)</label
          ><textarea id="status-note" formControlName="note" rows="3"></textarea>
          <p class="muted small-text">
            Use Close incident to record a resolution summary and close the record.
          </p>
        </fieldset>
        <div class="form-actions">
          <button type="button" class="button secondary" [disabled]="busy()" (click)="cancel()">
            Cancel</button
          ><button class="button" [disabled]="busy()">
            {{ busy() ? 'Updating...' : 'Update status' }}
          </button>
        </div>
      </form>
    }
    @if (mode() === 'assign') {
      <form [formGroup]="assignForm" (ngSubmit)="saveAssignment()">
        <fieldset [disabled]="busy() || assigneesLoading()">
          <legend>Assign owner</legend>
          @if (assigneesLoading()) {
            <p role="status">Loading active users...</p>
          }
          <app-error-notice [messages]="assigneeErrors()" />
          @if (assigneeErrors().length) {
            <button type="button" class="button secondary" (click)="loadAssignees()">
              Retry user list
            </button>
          }
          <label for="assignee">Assignee</label
          ><select id="assignee" formControlName="assignedToId">
            <option [ngValue]="null">Select an active user</option>
            @for (user of assignees(); track user.id) {
              <option [ngValue]="user.id">{{ user.fullName }}</option>
            }
          </select>
          @if (!assigneesLoading() && !assignees().length && !assigneeErrors().length) {
            <p class="muted">No active users are available.</p>
          }
          @if (assignForm.touched && assignForm.invalid) {
            <p class="field-error">Choose an assignee.</p>
          }
        </fieldset>
        <div class="form-actions">
          <button type="button" class="button secondary" [disabled]="busy()" (click)="cancel()">
            Cancel</button
          ><button
            class="button"
            [disabled]="busy() || assigneesLoading() || !!assigneeErrors().length"
          >
            {{ busy() ? 'Assigning...' : 'Assign owner' }}
          </button>
        </div>
      </form>
    }
    @if (mode() === 'escalate') {
      <form [formGroup]="escalateForm" (ngSubmit)="saveEscalate()" novalidate>
        <fieldset [disabled]="busy() || assigneesLoading()">
          <legend>Escalate case</legend>
          <label for="escalate-tier">Tier</label
          ><select id="escalate-tier" formControlName="tier">
            <option [ngValue]="1">Tier 1 — triage</option>
            <option [ngValue]="2">Tier 2 — investigation</option>
            <option [ngValue]="3">Tier 3 — incident response</option>
          </select>
          <label for="escalate-owner">Reassign to (optional)</label
          ><select id="escalate-owner" formControlName="assignedToId">
            <option [ngValue]="null">Keep current owner</option>
            @for (user of assignees(); track user.id) {
              <option [ngValue]="user.id">{{ user.fullName }}</option>
            }</select
          ><label for="escalate-note">Note (optional)</label
          ><textarea id="escalate-note" formControlName="note" rows="3"></textarea>
          <p class="muted small-text">
            Escalation can only raise the tier. Current tier: {{ incident().tier }}.
          </p>
        </fieldset>
        <div class="form-actions">
          <button type="button" class="button secondary" [disabled]="busy()" (click)="cancel()">
            Cancel</button
          ><button class="button" [disabled]="busy()">
            {{ busy() ? 'Escalating...' : 'Confirm escalation' }}
          </button>
        </div>
      </form>
    }
    @if (mode() === 'close') {
      <form [formGroup]="closeForm" (ngSubmit)="saveClose()" novalidate>
        <fieldset [disabled]="busy()">
          <legend>Close incident</legend>
          <label for="resolution">Resolution summary</label
          ><textarea
            id="resolution"
            formControlName="resolutionSummary"
            rows="4"
            placeholder="Describe the outcome and the steps taken."
          ></textarea>
          @if (closeForm.touched && closeForm.invalid) {
            <p class="field-error">A resolution summary is required.</p>
          }
        </fieldset>
        <div class="form-actions">
          <button type="button" class="button secondary" [disabled]="busy()" (click)="cancel()">
            Cancel</button
          ><button class="button" [disabled]="busy()">
            {{ busy() ? 'Closing...' : 'Confirm close' }}
          </button>
        </div>
      </form>
    }
  </section>`,
})
export class IncidentActions implements OnChanges {
  readonly incident = input.required<IncidentDetail>();
  readonly updated = output<IncidentDetail>();
  private readonly auth = inject(Auth);
  private readonly api = inject(Incidents);
  private readonly users = inject(Users);
  private readonly destroyRef = inject(DestroyRef);
  private readonly fb = inject(FormBuilder);
  protected readonly canManage = computed(() => this.auth.canManageIncidents());
  protected readonly canEdit = computed(
    () => this.canManage() || this.auth.user()?.id === this.incident().assignedToId,
  );
  protected readonly mode = signal<'edit' | 'status' | 'assign' | 'close' | 'escalate' | null>(
    null,
  );
  protected readonly busy = signal(false);
  protected readonly errors = signal<string[]>([]);
  protected readonly success = signal('');
  protected readonly conflict = signal(false);
  protected readonly assignees = signal<Assignee[]>([]);
  protected readonly assigneesLoading = signal(false);
  protected readonly assigneeErrors = signal<string[]>([]);
  protected readonly severities = severities;
  protected readonly priorities = priorities;
  protected readonly categories = categories;
  protected readonly statusOptions = statuses
    .map((label, value) => ({ label, value }))
    .filter((o) => o.value !== 7);
  protected readonly editForm = this.fb.nonNullable.group({
    title: ['', [Validators.required, Validators.maxLength(200), Validators.pattern(/\S/)]],
    description: ['', [Validators.required, Validators.pattern(/\S/)]],
    severity: [1],
    priority: [1],
    category: [9],
  });
  protected readonly statusForm = this.fb.nonNullable.group({ status: [0], note: [''] });
  protected readonly escalateForm = this.fb.nonNullable.group({
    tier: [1],
    assignedToId: this.fb.control<number | null>(null),
    note: [''],
  });
  protected readonly assignForm = this.fb.group({
    assignedToId: this.fb.control<number | null>(null, Validators.required),
  });
  protected readonly closeForm = this.fb.nonNullable.group({
    resolutionSummary: ['', [Validators.required, Validators.pattern(/\S/)]],
  });
  ngOnChanges(): void {
    this.resetForms();
  }
  private resetForms(): void {
    const i = this.incident();
    this.editForm.reset({
      title: i.title,
      description: i.description,
      severity: i.severity,
      priority: i.priority,
      category: i.category,
    });
    this.statusForm.reset({ status: i.status === 7 ? 6 : i.status, note: '' });
    this.assignForm.reset({ assignedToId: i.assignedToId });
    this.closeForm.reset();
  }
  protected open(mode: 'edit' | 'status' | 'assign' | 'close' | 'escalate'): void {
    if (this.busy()) return;
    this.resetForms();
    this.mode.set(mode);
    this.errors.set([]);
    this.success.set('');
    this.conflict.set(false);
    if (mode === 'assign' || mode === 'escalate') this.loadAssignees();
    if (mode === 'escalate')
      this.escalateForm.reset({ tier: this.incident().tier, assignedToId: null, note: '' });
  }
  protected cancel(): void {
    this.mode.set(null);
    this.errors.set([]);
    this.conflict.set(false);
  }
  protected loadAssignees(): void {
    this.assigneesLoading.set(true);
    this.assigneeErrors.set([]);
    this.users
      .assignable()
      .pipe(
        takeUntilDestroyed(this.destroyRef),
        finalize(() => this.assigneesLoading.set(false)),
      )
      .subscribe({
        next: (list) => {
          this.assignees.set(list);
          if (!list.some((u) => u.id === this.assignForm.value.assignedToId))
            this.assignForm.reset();
        },
        error: (e) => this.assigneeErrors.set(apiErrors(e)),
      });
  }
  private run(request: Observable<IncidentDetail>, message: string): void {
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
        next: (value) => {
          this.updated.emit(value);
          this.mode.set(null);
          this.conflict.set(false);
          this.success.set(message);
        },
        error: (e) => {
          this.errors.set(apiErrors(e));
          if (e instanceof HttpErrorResponse && e.status === 409) this.conflict.set(true);
        },
      });
  }
  protected saveEdit(): void {
    this.editForm.markAllAsTouched();
    if (!this.canEdit() || this.editForm.invalid || this.conflict()) return;
    const value = this.editForm.getRawValue();
    this.run(
      this.api.update(this.incident().id, {
        ...value,
        title: value.title.trim(),
        description: value.description.trim(),
        version: this.incident().version,
      }),
      'Incident updated.',
    );
  }
  protected saveStatus(): void {
    if (!this.canEdit() || this.statusForm.invalid) return;
    const value = this.statusForm.getRawValue();
    this.run(
      this.api.changeStatus(this.incident().id, value.status, value.note.trim() || null),
      'Status updated.',
    );
  }
  protected saveAssignment(): void {
    this.assignForm.markAllAsTouched();
    const id = this.assignForm.value.assignedToId;
    if (!this.canManage() || !id || !this.assignees().some((u) => u.id === id)) return;
    this.run(this.api.assign(this.incident().id, id), 'Owner assigned.');
  }
  protected saveEscalate(): void {
    if (!this.canManage()) return;
    const value = this.escalateForm.getRawValue();
    const assignee =
      value.assignedToId && this.assignees().some((u) => u.id === value.assignedToId)
        ? value.assignedToId
        : null;
    this.run(
      this.api.escalate(this.incident().id, value.tier, assignee, value.note.trim() || null),
      'Case escalated.',
    );
  }
  protected saveClose(): void {
    this.closeForm.markAllAsTouched();
    if (!this.canManage() || this.closeForm.invalid) return;
    this.run(
      this.api.close(this.incident().id, this.closeForm.getRawValue().resolutionSummary.trim()),
      'Incident closed.',
    );
  }
  protected loadLatest(): void {
    this.run(this.api.detail(this.incident().id), 'Latest record loaded. You can edit it again.');
  }
}
