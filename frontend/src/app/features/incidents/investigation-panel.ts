import { InfoPopup } from '../../shared/components/detail-modal';
import { Component, DestroyRef, OnChanges, inject, input, signal } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { RouterLink } from '@angular/router';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { finalize, Subscription } from 'rxjs';
import { DataForm, Field, choices } from '../../shared/components/data-form';
import { ErrorNotice } from '../../shared/components/error-notice';
import {
  RecordRow,
  selectField,
  textField,
  iocTypes,
  iocRoles,
  impactTypes,
  confidence,
} from '../../core/models/catalog';
import { apiErrors } from '../../core/services/api-errors';
import { utcTimestamp } from '../../core/services/incidents';
const actionTypes = [
  'Disable user',
  'Block IP',
  'Block domain',
  'Block hash',
  'Isolate endpoint',
  'Reset password',
  'Remove malware',
  'Reimage device',
  'Revoke sessions',
  'Patch system',
  'Restore backup',
  'Other',
];
const actionStatuses = ['Planned', 'In progress', 'Completed', 'Failed', 'Rolled back'];
const eventTypes = [
  'Detection',
  'Alert received',
  'Status change',
  'Assignment',
  'IOC identified',
  'Containment action',
  'Evidence added',
  'Analyst note',
  'Communication',
  'Escalation',
  'Resolution',
  'Other',
];
@Component({
  selector: 'app-investigation',
  imports: [InfoPopup,DataForm, ErrorNotice, RouterLink],
  template: ` <section class="panel panel-padding">
    <div class="action-toolbar">
      <div>
        <p class="eyebrow">INVESTIGATION WORKSPACE</p>
        <h2>Activity &amp; connected evidence</h2>
      </div>
      <button class="button secondary small" (click)="load()" [disabled]="loading() || busy()">
        Refresh workspace
      </button>
    </div>
    <div class="tab-strip" role="group" aria-label="Investigation sections">
      @for (item of tabs; track item.key) {
        <button
          [class.selected]="tab() === item.key"
          [attr.aria-pressed]="tab() === item.key"
          (click)="choose(item.key)"
          [disabled]="busy()"
        >
          {{ item.label }}
        </button>
      }
    </div>
    <app-error-notice [messages]="errors()" />
    @if (message()) {
      <p class="success-notice" role="status">{{ message() }}</p>
    }
    @if (loading()) {
      <p role="status">Loading records...</p>
    } @else if (!rows().length) {
      <p class="notice">Nothing recorded in this section yet.</p>
    }
    <div class="activity-feed">
      @for (row of rows(); track row.id) {
        <article class="activity-item">
          <span class="activity-node"></span>
          <div class="action-toolbar">
            <strong class="break-word">{{
              row['title'] ||
                row['name'] ||
                row['authorName'] ||
                actionTypes[+number(row['actionType'])] ||
                'Record'
            }}</strong
            ><small>{{
              date(row['occurredAt'] || row['createdAt'] || row['addedAt'] || row['plannedAt'])
            }}</small>
          </div>
          <p class="description">{{ row['body'] || row['description'] || row['notes'] }}</p>
          @if (row['reference']) {
            <code>{{ row['reference'] }}</code>
          }
          @if (row['classification'] !== null && row['classification'] !== undefined) {
            <span class="badge neutral">{{
              tab() === 'iocs'
                ? iocRoles[number(row['classification'])]
                : impactTypes[number(row['classification'])]
            }}</span>
          }
          @if (row['isInternal']) {
            <span class="badge neutral">Internal</span>
          }
          @if (row['isSystemGenerated']) {
            <span class="badge neutral">System event</span>
          }
          @if (row['actorName']) {
            <small>Recorded by {{ row['actorName'] }}</small>
          }
          @if (tab() === 'response-actions') {
            <p>
              <span class="badge neutral">{{ actionStatuses[number(row['status'])] }}</span>
              &middot; {{ row['performedByName'] }}
            </p>
            <p>{{ row['result'] }}</p>
            <app-info-popup title="Update action outcome"><span popupTrigger>Update action outcome</span>
              <app-data-form
                [fields]="updateFields"
                [value]="row"
                [prefix]="'action-' + row.id + '-'"
                [busy]="busy()"
                label="Save outcome"
                (saved)="updateAction(row.id, $event)"
              />
            </app-info-popup>
          }
          @if (isLink()) {
            <div class="button-row">
              <a
                [routerLink]="[
                  tab() === 'mitre-techniques' ? '/attack-matrix' : '/' + tab(),
                  tab() === 'mitre-techniques' ? row['reference'] : row.id,
                ]"
                >View record &rarr;</a
              ><button
                class="link-button danger-text"
                (click)="pending.set(row.id)"
                [disabled]="busy()"
              >
                Unlink
              </button>
            </div>
            @if (pending() === row.id) {
              <div class="confirm-box">
                <p>Remove this association? The catalog record is kept.</p>
                <button class="button danger small" (click)="unlink(row.id)" [disabled]="busy()">
                  Confirm unlink</button
                ><button class="button secondary small" (click)="pending.set(null)">Cancel</button>
              </div>
            }
          }
        </article>
      }
    </div>
    <hr />
    <h3>{{ isLink() ? 'Add association' : 'Add record' }}</h3>
    <p class="muted small-text">
      {{
        isLink()
          ? 'Choose an existing record or identify a new indicator.'
          : 'Response actions record work performed by your team; adding one does not execute a command.'
      }}
    </p>
    @if (tab() === 'assets' || tab() === 'mitre-techniques') {
      <div class="filter-bar">
        <label
          >Find a record<input
            #lookupInput
            placeholder="Name, technique ID or asset name"
            (input)="find(lookupInput.value)" /></label
        ><button
          class="button secondary small"
          [disabled]="lookupPage <= 1"
          (click)="find(lookupInput.value, lookupPage - 1)"
        >
          Previous</button
        ><button
          class="button secondary small"
          [disabled]="!lookupNext"
          (click)="find(lookupInput.value, lookupPage + 1)"
        >
          Next
        </button>
      </div>
      <p class="muted small-text">
        Assets are browsed 25 at a time; name matching applies to the current page.
      </p>
    }
    <app-data-form
      [fields]="fields()"
      [busy]="busy()"
      [prefix]="'investigation-' + tab() + '-'"
      label="Add to investigation"
      (saved)="add($event)"
    />
  </section>`,
})
export class InvestigationPanel implements OnChanges {
  readonly incidentId = input.required<number>();
  private http = inject(HttpClient);
  private destroy = inject(DestroyRef);
  private request?: Subscription;
  private lookupRequest?: Subscription;
  protected tab = signal('comments');
  protected rows = signal<RecordRow[]>([]);
  protected fields = signal<Field[]>([]);
  protected errors = signal<string[]>([]);
  protected message = signal('');
  protected loading = signal(false);
  protected busy = signal(false);
  protected pending = signal<number | null>(null);
  protected lookupPage = 1;
  protected lookupNext = false;
  protected readonly tabs = [
    { key: 'comments', label: 'Discussion' },
    { key: 'timeline', label: 'Timeline' },
    { key: 'response-actions', label: 'Response actions' },
    { key: 'iocs', label: 'Indicators' },
    { key: 'assets', label: 'Assets' },
    { key: 'mitre-techniques', label: 'MITRE mappings' },
  ];
  protected readonly actionTypes = actionTypes;
  protected readonly actionStatuses = actionStatuses;
  protected readonly iocRoles = iocRoles;
  protected readonly impactTypes = impactTypes;
  protected readonly updateFields: Field[] = [
    selectField('status', 'Status', actionStatuses),
    { key: 'result', label: 'Outcome', type: 'textarea' },
  ];
  ngOnChanges() {
    this.choose('comments');
  }
  protected number(v: unknown) {
    return Number(v);
  }
  protected date(v: unknown) {
    return v ? new Date(utcTimestamp(String(v))).toLocaleString() : '';
  }
  protected isLink() {
    return ['iocs', 'assets', 'mitre-techniques'].includes(this.tab());
  }
  private url() {
    return '/api/incidents/' + this.incidentId() + '/' + this.tab();
  }
  protected choose(tab: string) {
    this.tab.set(tab);
    this.message.set('');
    this.pending.set(null);
    this.lookupRequest?.unsubscribe();
    this.fields.set(this.formFields(tab));
    this.load();
    if (['assets', 'mitre-techniques'].includes(tab)) this.find('');
  }
  protected load() {
    this.request?.unsubscribe();
    this.loading.set(true);
    this.errors.set([]);
    this.request = this.http
      .get<RecordRow[]>(this.url())
      .pipe(
        takeUntilDestroyed(this.destroy),
        finalize(() => this.loading.set(false)),
      )
      .subscribe({
        next: (r) => this.rows.set(r),
        error: (e) => {
          this.rows.set([]);
          this.errors.set(apiErrors(e));
        },
      });
  }
  private formFields(tab: string): Field[] {
    const notes: Field = { key: 'notes', label: 'Context / notes', type: 'textarea' };
    switch (tab) {
      case 'comments':
        return [
          { key: 'body', label: 'Comment', type: 'textarea', required: true },
          {
            key: 'isInternal',
            label: 'Visibility',
            type: 'select',
            initial: true,
            options: [
              { label: 'Internal', value: true },
              { label: 'General', value: false },
            ],
          },
        ];
      case 'timeline':
        return [
          textField('title', 'Event title', true),
          selectField('eventType', 'Event type', eventTypes, 7),
          { key: 'occurredAt', label: 'Occurred at', type: 'datetime-local', required: true },
          { key: 'description', label: 'Details', type: 'textarea' },
        ];
      case 'response-actions':
        return [
          selectField('actionType', 'Action', actionTypes),
          { key: 'description', label: 'Description', type: 'textarea', required: true },
          selectField('targetType', 'Target type', ['Asset', 'User', 'IOC', 'Other'], 3),
          textField('targetValue', 'Target value'),
          { key: 'targetAssetId', label: 'Known asset ID (optional)', type: 'number' },
        ];
      case 'iocs':
        return [
          selectField('type', 'Type', iocTypes),
          textField('value', 'Indicator value', true, 512),
          selectField('confidence', 'Confidence', confidence),
          selectField('role', 'Role in incident', iocRoles, 6),
          notes,
        ];
      case 'assets':
        return [
          { key: 'assetId', label: 'Asset', type: 'select', required: true, options: [] },
          selectField('impactType', 'Impact', impactTypes, 1),
          notes,
        ];
      default:
        return [
          {
            key: 'mitreTechniqueId',
            label: 'Technique',
            type: 'select',
            required: true,
            options: [],
          },
          notes,
        ];
    }
  }
  protected find(search: string, page = 1) {
    this.lookupRequest?.unsubscribe();
    this.lookupPage = page;
    const asset = this.tab() === 'assets';
    const params: Record<string, string> = asset
      ? { page: String(page), pageSize: '25' }
      : { search };
    this.lookupRequest = this.http
      .get<RecordRow[] | { items: RecordRow[]; hasNextPage: boolean }>(
        asset ? '/api/assets' : '/api/mitre/techniques',
        { params },
      )
      .pipe(takeUntilDestroyed(this.destroy))
      .subscribe({
        next: (r) => {
          const list = Array.isArray(r) ? r : r.items;
          this.lookupNext = !Array.isArray(r) && r.hasNextPage;
          const fields = this.formFields(this.tab());
          fields[0].options = [
            { label: 'Select a record', value: null },
            ...list
              .filter(
                (x) => !asset || String(x['name']).toLowerCase().includes(search.toLowerCase()),
              )
              .map((x) => ({
                label: String(x['techniqueId'] ?? '') + ' ' + String(x['name']),
                value: x.id,
              })),
          ];
          this.fields.set(fields);
        },
        error: (e) => this.errors.set(apiErrors(e)),
      });
  }
  protected add(data: Record<string, unknown>) {
    const value = { ...data };
    if (value['occurredAt'])
      value['occurredAt'] = new Date(String(value['occurredAt'])).toISOString();
    if ('targetAssetId' in value)
      value['targetAssetId'] =
        value['targetAssetId'] === '' ? null : Number(value['targetAssetId']);
    this.mutate('POST', this.url(), value);
  }
  protected updateAction(id: number, data: Record<string, unknown>) {
    this.mutate('PUT', this.url() + '/' + id, data);
  }
  protected unlink(id: number) {
    if (this.pending() !== id) return;
    this.mutate('DELETE', this.url() + '/' + id);
  }
  private mutate(method: string, url: string, body?: unknown) {
    if (this.busy()) return;
    this.busy.set(true);
    this.errors.set([]);
    this.http
      .request(method, url, { body })
      .pipe(
        takeUntilDestroyed(this.destroy),
        finalize(() => this.busy.set(false)),
      )
      .subscribe({
        next: () => {
          this.pending.set(null);
          this.message.set('Investigation updated.');
          this.fields.set(this.formFields(this.tab()));
          if (['assets', 'mitre-techniques'].includes(this.tab())) this.find('');
          this.load();
        },
        error: (e) => this.errors.set(apiErrors(e)),
      });
  }
}
