import { InfoPopup } from '../../shared/components/detail-modal';
import { DatePipe, DecimalPipe } from '@angular/common';
import { Component, DestroyRef, OnChanges, inject, input, signal } from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { FormBuilder, ReactiveFormsModule } from '@angular/forms';
import { Subscription, finalize } from 'rxjs';
import { EvidenceFile, evidenceTypes } from '../../core/models/operations';
import { Evidence, Downloads, evidenceExtensions, fileError } from '../../core/services/evidence';
import { Auth } from '../../core/services/auth';
import { apiErrors } from '../../core/services/api-errors';
import { ErrorNotice } from '../../shared/components/error-notice';
@Component({
  selector: 'app-evidence',
  imports: [InfoPopup,ReactiveFormsModule, DatePipe, DecimalPipe, ErrorNotice],
  template: ` <section class="panel panel-padding">
    <div class="action-toolbar">
      <div>
        <h2>Evidence</h2>
        <p class="muted small-text">
          Files collected for this incident. Downloads are recorded in the audit log.
        </p>
      </div>
      <button class="button secondary small" (click)="load()" [disabled]="loading() || !!busy()">
        Refresh files
      </button>
    </div>
    @if (success()) {
      <p class="success-notice" role="status">{{ success() }}</p>
    }
    <app-error-notice [messages]="errors()" /><app-error-notice [messages]="listErrors()" />
    @if (loading()) {
      <p role="status">Loading evidence...</p>
    }
    @if (listErrors().length) {
      <button class="button secondary" (click)="load()">Retry files</button>
    }
    @if (!loading() && !listErrors().length) {
      @if (!files().length) {
        <p class="notice">No evidence uploaded yet.</p>
      }
      <ul class="evidence-list">
        @for (file of files(); track file.id) {
          <li>
            <div class="action-toolbar">
              <div class="file-info">
                <strong class="break-word">{{ file.originalFileName }}</strong>
                <p class="muted small-text">
                  {{ types.at(file.evidenceType) ?? 'Other' }} &middot;
                  {{ file.sizeBytes / 1024 | number: '1.0-1' }} KB &middot;
                  {{ file.uploadedByName }} &middot; {{ file.uploadedAt | date: 'medium' }}
                </p>
              </div>
              <div class="button-row">
                <button
                  class="button secondary small"
                  [disabled]="!!busy()"
                  (click)="download(file)"
                >
                  {{ busy() === 'download-' + file.id ? 'Downloading...' : 'Download' }}
                </button>
                @if (auth.canManageIncidents()) {
                  <button
                    class="button danger-outline small"
                    [disabled]="!!busy()"
                    (click)="pendingDelete.set(file.id)"
                  >
                    Delete
                  </button>
                }
              </div>
            </div>
            @if (file.description) {
              <p class="description">{{ file.description }}</p>
            }
            <app-info-popup title="SHA-256 checksum"><span popupTrigger>SHA-256 checksum</span>
              <code class="checksum">{{ file.sha256 }}</code>
            </app-info-popup>
            @if (pendingDelete() === file.id) {
              <div class="confirm-box" role="group" aria-label="Confirm evidence deletion">
                <p>
                  Delete <strong>{{ file.originalFileName }}</strong
                  >? The file will be permanently removed.
                </p>
                <div class="button-row">
                  <button class="button danger" [disabled]="!!busy()" (click)="remove(file)">
                    {{ busy() ? 'Deleting...' : 'Confirm delete' }}</button
                  ><button
                    class="button secondary"
                    [disabled]="!!busy()"
                    (click)="pendingDelete.set(null)"
                  >
                    Keep file
                  </button>
                </div>
              </div>
            }
          </li>
        }
      </ul>
    }
    <hr />
    <h3>Upload evidence</h3>
    <form [formGroup]="form" (ngSubmit)="upload(fileInput)">
      <fieldset [disabled]="!!busy()">
        <label for="evidence-file">File</label
        ><input
          #fileInput
          id="evidence-file"
          type="file"
          [accept]="extensions"
          (change)="chooseFile($event)"
          aria-describedby="evidence-help"
        /><small id="evidence-help"
          >Images, text/logs, CSV, JSON, XML, PDF, Office documents, packet captures, and ZIP
          archives. The server enforces the file size limit.</small
        >
        <div class="form-grid">
          <div>
            <label for="evidence-type">Evidence type</label
            ><select id="evidence-type" formControlName="type">
              @for (type of types; track $index) {
                <option [ngValue]="$index">{{ type }}</option>
              }
            </select>
          </div>
          <div>
            <label for="evidence-description">Description (optional)</label
            ><input id="evidence-description" formControlName="description" />
          </div>
        </div>
      </fieldset>
      <div class="form-actions">
        <button class="button" [disabled]="!!busy() || !selectedFile()">
          {{ busy() === 'upload' ? 'Uploading...' : 'Upload evidence' }}
        </button>
      </div>
    </form>
  </section>`,
})
export class EvidencePanel implements OnChanges {
  readonly incidentId = input.required<number>();
  protected readonly auth = inject(Auth);
  private readonly api = inject(Evidence);
  private readonly downloads = inject(Downloads);
  private readonly destroyRef = inject(DestroyRef);
  private listRequest?: Subscription;
  protected readonly files = signal<EvidenceFile[]>([]);
  protected readonly loading = signal(false);
  protected readonly listErrors = signal<string[]>([]);
  protected readonly errors = signal<string[]>([]);
  protected readonly success = signal('');
  protected readonly busy = signal('');
  protected readonly selectedFile = signal<File | null>(null);
  protected readonly pendingDelete = signal<number | null>(null);
  protected readonly types = evidenceTypes;
  protected readonly extensions = evidenceExtensions;
  protected readonly form = inject(FormBuilder).nonNullable.group({ type: [7], description: [''] });
  ngOnChanges(): void {
    this.files.set([]);
    this.errors.set([]);
    this.success.set('');
    this.pendingDelete.set(null);
    this.load();
  }
  protected load(): void {
    this.listRequest?.unsubscribe();
    this.loading.set(true);
    this.listErrors.set([]);
    this.listRequest = this.api
      .list(this.incidentId())
      .pipe(
        takeUntilDestroyed(this.destroyRef),
        finalize(() => this.loading.set(false)),
      )
      .subscribe({
        next: (list) => this.files.set(list),
        error: (e) => this.listErrors.set(apiErrors(e)),
      });
  }
  protected chooseFile(event: Event): void {
    const file = (event.target as HTMLInputElement).files?.[0] ?? null;
    const error = file ? fileError(file) : null;
    this.selectedFile.set(error ? null : file);
    this.errors.set(error ? [error] : []);
    this.success.set('');
  }
  protected upload(input: HTMLInputElement): void {
    const file = this.selectedFile();
    if (!file || this.busy()) return;
    this.busy.set('upload');
    this.errors.set([]);
    this.success.set('');
    const value = this.form.getRawValue();
    this.api
      .upload(this.incidentId(), file, value.type, value.description)
      .pipe(
        takeUntilDestroyed(this.destroyRef),
        finalize(() => this.busy.set('')),
      )
      .subscribe({
        next: () => {
          input.value = '';
          this.selectedFile.set(null);
          this.form.reset();
          this.success.set('Evidence uploaded.');
          this.load();
        },
        error: (e) => this.errors.set(apiErrors(e)),
      });
  }
  protected download(file: EvidenceFile): void {
    if (this.busy()) return;
    this.busy.set('download-' + file.id);
    this.errors.set([]);
    this.api
      .download(this.incidentId(), file.id)
      .pipe(
        takeUntilDestroyed(this.destroyRef),
        finalize(() => this.busy.set('')),
      )
      .subscribe({
        next: (blob) => this.downloads.save(blob, file.originalFileName),
        error: (e) => this.errors.set(apiErrors(e)),
      });
  }
  protected remove(file: EvidenceFile): void {
    if (this.busy() || !this.auth.canManageIncidents() || this.pendingDelete() !== file.id) return;
    this.busy.set('delete-' + file.id);
    this.errors.set([]);
    this.api
      .delete(this.incidentId(), file.id)
      .pipe(
        takeUntilDestroyed(this.destroyRef),
        finalize(() => this.busy.set('')),
      )
      .subscribe({
        next: () => {
          this.files.update((list) => list.filter((f) => f.id !== file.id));
          this.pendingDelete.set(null);
          this.success.set('Evidence deleted.');
        },
        error: (e) => this.errors.set(apiErrors(e)),
      });
  }
}
