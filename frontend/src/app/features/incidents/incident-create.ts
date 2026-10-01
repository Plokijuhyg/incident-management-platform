import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { Component, DestroyRef, inject, signal } from '@angular/core';
import {
  AbstractControl,
  FormBuilder,
  ReactiveFormsModule,
  ValidationErrors,
  Validators,
} from '@angular/forms';
import { Router, RouterLink } from '@angular/router';
import { finalize } from 'rxjs';
import { categories, priorities, severities, sources } from '../../core/models/api';
import { Incidents } from '../../core/services/incidents';
import { apiErrors } from '../../core/services/api-errors';
import { ErrorNotice } from '../../shared/components/error-notice';
export function milestoneOrder(control: AbstractControl): ValidationErrors | null {
  const occurred = control.get('occurredAt')?.value as string;
  const detected = control.get('detectedAt')?.value as string;
  if (
    (occurred && !Number.isFinite(Date.parse(occurred))) ||
    (detected && !Number.isFinite(Date.parse(detected)))
  )
    return { milestoneOrder: true };
  return occurred && (!detected || Date.parse(occurred) > Date.parse(detected))
    ? { milestoneOrder: true }
    : null;
}
@Component({
  imports: [ReactiveFormsModule, RouterLink, ErrorNotice],
  template: ` <a class="back-link" routerLink="/incidents">&larr; All incidents</a>
    <div class="page-heading">
      <div>
        <p class="eyebrow">INCIDENT RESPONSE</p>
        <h1>Create an incident</h1>
        <p class="muted">Capture what you know. Give your team a clear starting point.</p>
      </div>
    </div>
    <div class="create-grid">
      <form class="panel panel-padding" [formGroup]="form" (ngSubmit)="submit()" novalidate>
        <app-error-notice [messages]="errors()" />
        <fieldset [disabled]="busy()">
          <legend>Incident information</legend>
          <p class="muted small-text">All fields are required unless marked optional.</p>
          <label for="title">Title</label
          ><input
            id="title"
            formControlName="title"
            maxlength="200"
            placeholder="Summarize the incident"
            aria-describedby="title-help"
            [attr.aria-invalid]="invalid('title')"
          /><small id="title-help" [class.field-error]="invalid('title')">{{
            invalid('title')
              ? 'Enter a title of up to 200 characters.'
              : 'A short, specific description. Maximum 200 characters.'
          }}</small>
          <label for="description">Description</label
          ><textarea
            id="description"
            formControlName="description"
            rows="6"
            placeholder="What happened? Include the scope and relevant context."
            [attr.aria-invalid]="invalid('description')"
            aria-describedby="description-error"
          ></textarea>
          @if (invalid('description')) {
            <small id="description-error" class="field-error">Enter a description.</small>
          }
          <div class="form-grid">
            <div>
              <label for="severity">Severity</label
              ><select id="severity" formControlName="severity">
                @for (label of severities; track $index) {
                  <option [ngValue]="$index">{{ label }}</option>
                }
              </select>
            </div>
            <div>
              <label for="priority">Priority</label
              ><select id="priority" formControlName="priority">
                @for (label of priorities; track $index) {
                  <option [ngValue]="$index">{{ label }}</option>
                }
              </select>
            </div>
            <div>
              <label for="category">Category</label
              ><select id="category" formControlName="category">
                @for (label of categories; track $index) {
                  <option [ngValue]="$index">{{ label }}</option>
                }
              </select>
            </div>
            <div>
              <label for="source">Source</label
              ><select id="source" formControlName="source">
                @for (label of sources; track $index) {
                  <option [ngValue]="$index">{{ label }}</option>
                }
              </select>
            </div>
          </div>
          <hr />
          <h2>Timing <span class="muted small-text">(optional)</span></h2>
          <p class="muted small-text">
            Enter times in your local timezone. Leave unknown times empty.
          </p>
          <div class="form-grid">
            <div>
              <label for="detectedAt">Detected at</label
              ><input
                id="detectedAt"
                type="datetime-local"
                formControlName="detectedAt"
                aria-describedby="timing-error"
              />
            </div>
            <div>
              <label for="occurredAt">Occurred at</label
              ><input
                id="occurredAt"
                type="datetime-local"
                formControlName="occurredAt"
                aria-describedby="timing-error"
              />
            </div>
          </div>
          @if (form.touched && form.hasError('milestoneOrder')) {
            <small class="field-error" id="timing-error"
              >Enter valid dates. Occurrence requires a detection time and must not be later than
              detection.</small
            >
          }
        </fieldset>
        <div class="form-actions">
          <a class="button secondary" routerLink="/incidents">Cancel</a
          ><button class="button" type="submit" [disabled]="busy()">
            {{ busy() ? 'Creating incident...' : 'Create incident' }}
          </button>
        </div>
      </form>
      <aside class="creation-notes">
        <span class="note-icon" aria-hidden="true">i</span>
        <h2>A useful first report</h2>
        <p>Describe the activity, affected systems, and what prompted the investigation.</p>
        <h3>Severity and priority</h3>
        <p>Severity captures the impact. Priority tells the team how urgently to respond.</p>
        <h3>Keep the timeline accurate</h3>
        <p>
          Occurrence is when the activity began. Detection is when it was discovered. Unknown is
          better than an estimate presented as fact.
        </p>
      </aside>
    </div>`,
})
export class IncidentCreate {
  private readonly destroyRef = inject(DestroyRef);
  private readonly incidents = inject(Incidents);
  private readonly router = inject(Router);
  protected readonly severities = severities;
  protected readonly priorities = priorities;
  protected readonly categories = categories;
  protected readonly sources = sources;
  protected readonly busy = signal(false);
  protected readonly errors = signal<string[]>([]);
  protected readonly form = inject(FormBuilder).nonNullable.group(
    {
      title: ['', [Validators.required, Validators.maxLength(200), Validators.pattern(/\S/)]],
      description: ['', [Validators.required, Validators.pattern(/\S/)]],
      severity: [1, Validators.required],
      priority: [1, Validators.required],
      category: [9, Validators.required],
      source: [5, Validators.required],
      detectedAt: [''],
      occurredAt: [''],
    },
    { validators: milestoneOrder },
  );
  protected invalid(field: 'title' | 'description'): boolean {
    return this.form.controls[field].touched && this.form.controls[field].invalid;
  }
  protected submit(): void {
    this.form.markAllAsTouched();
    if (this.form.invalid || this.busy()) return;
    this.busy.set(true);
    this.errors.set([]);
    const value = this.form.getRawValue();
    this.incidents
      .create({
        ...value,
        title: value.title.trim(),
        description: value.description.trim(),
        detectedAt: value.detectedAt ? new Date(value.detectedAt).toISOString() : null,
        occurredAt: value.occurredAt ? new Date(value.occurredAt).toISOString() : null,
      })
      .pipe(
        takeUntilDestroyed(this.destroyRef),
        finalize(() => this.busy.set(false)),
      )
      .subscribe({
        next: (incident) => void this.router.navigate(['/incidents', incident.id]),
        error: (error) => this.errors.set(apiErrors(error)),
      });
  }
}
