import { InfoPopup } from '../../shared/components/detail-modal';
import { Component, DestroyRef, inject, signal } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { RouterLink } from '@angular/router';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { finalize } from 'rxjs';
import { ErrorNotice } from '../../shared/components/error-notice';
import { apiErrors } from '../../core/services/api-errors';
interface Connections {
  hexStrikeUrl: string;
  ollamaUrl: string;
}
interface Result {
  service: string;
  url: string;
  reachable: boolean;
  message: string;
  checkedAt: string;
}
@Component({
  imports: [InfoPopup,RouterLink, ErrorNotice],
  template: `<div class="page-heading">
      <div>
        <p class="eyebrow">AUTHORIZED LABORATORY</p>
        <h1>Lab connections</h1>
        <p class="muted">Prepare your local security tools and private analysis environment.</p>
      </div>
      <span class="badge neutral">Administrator settings</span>
    </div>
    <app-error-notice [messages]="errors()" />
    <div class="lab-architecture">
      <span>Incident Platform</span><b>&rarr;</b><span>HexStrike / Kali</span><b>&rarr;</b
      ><span>Approved lab target</span>
    </div>
    <div class="dashboard-grid">
      @for (service of services; track service.key) {
        <section class="panel panel-padding integration-card">
          <div class="integration-icon">{{ service.icon }}</div>
          <h2>{{ service.label }}</h2>
          <p class="muted">{{ service.description }}</p>
          <span
            class="badge"
            [class.severity-0]="results()[service.key]?.reachable"
            [class.neutral]="!results()[service.key]?.reachable"
            >{{
              results()[service.key]
                ? results()[service.key].reachable
                  ? 'Connected'
                  : 'Unavailable'
                : 'Not checked'
            }}</span
          >
          <dl>
            <dt>Configured endpoint</dt>
            <dd>
              <code>{{ url(service.key) }}</code>
            </dd>
          </dl>
          @if (results()[service.key]; as result) {
            <p role="status">{{ result.message }}</p>
            <small>Checked {{ time(result.checkedAt) }}</small>
          }
          <button
            class="button secondary"
            [disabled]="busy() || !config()"
            (click)="check(service.key)"
          >
            {{ busy() === service.key ? 'Checking...' : 'Test connection' }}
          </button>
        </section>
      }
    </div>
    <section class="panel panel-padding">
      <h2>Incident email notifications</h2>
      <p>SMTP is optional. Delivery runs separately from incident creation and requires configured recipients.</p>
      <button class="button secondary" [disabled]="notificationBusy()" (click)="checkNotifications()">Check email configuration</button>
      @if (notifications(); as status) {
        <p role="status">{{ status.enabled && status.configured ? 'Enabled and configured' : 'Email delivery is not ready' }} &middot; Minimum severity: {{ status.minimumSeverity }}</p>
        @for (key of status.missing; track key) { <p><code>{{ key }}</code> is missing or invalid.</p> }
        @for (item of status.counts; track item.state) { <span class="badge neutral">{{ item.state }}: {{ item.count }}</span> }
      }
    </section>
    <section class="panel panel-padding">
      <h2>Connection configuration</h2>
      <p>
        Endpoints are configured on the API server. The browser never receives service credentials.
      </p>
      <app-info-popup title="Local setup commands"><span popupTrigger>Local setup commands</span>
        <p class="muted">
          Run these in the repository root, then restart the backend. Keep HexStrike accessible
          through a private authenticated connection or local tunnel.
        </p>
        <pre class="raw-output">
.\\scripts\\Start-LabConnections.ps1

dotnet user-secrets set "Lab:HexStrikeUrl" "http://127.0.0.1:8888" --project backend/IncidentPlatform.Api
 dotnet user-secrets set "Lab:OllamaUrl" "http://127.0.0.1:11434" --project backend/IncidentPlatform.Api</pre>
      </app-info-popup>
      <p class="notice">
        A successful connection test checks the service only; it
        does not validate a model, MCP session or assessment workflow.
      </p>
    </section>
    <section class="panel panel-padding">
      <h2>Assessment readiness</h2>
      <button class="button secondary" [disabled]="gatewayBusy()" (click)="checkGateway()">{{ gatewayBusy() ? 'Checking MCP...' : 'Check assessment gateway' }}</button>
      @if (gateway(); as status) {
        <p role="status">{{ status.message }}</p>
        <p>{{ status.connected ? 'Live MCP connected' : 'Gateway or MCP unavailable' }} &middot; {{ availableTools() }} executable tools</p>
      }
      <a class="button secondary" routerLink="/assessments">Open assessments</a>
      <p>
        Open Assessments to select an approved target and specific tools from the live MCP manifest.
        HexStrike health on port 8888 and the authenticated assessment gateway on port 9443 are separate checks.
      </p>
      <div class="button-row">
        <a class="button" routerLink="/alerts">Review security alerts &rarr;</a
        ><a class="button secondary" routerLink="/audit">Inspect audit trail</a>
      </div>
    </section>`,
})
export class LabPage {
  protected gateway = signal<{connected:boolean; message:string; tools?:{available:boolean}[]} | null>(null);
  protected gatewayBusy = signal(false);
  protected availableTools() { return this.gateway()?.tools?.filter(t=>t.available).length ?? 0; }
  protected checkGateway() {
    this.gatewayBusy.set(true);
    this.http.get<{connected:boolean;message:string;tools?:{available:boolean}[]}>('/api/assessments/capabilities').pipe(takeUntilDestroyed(this.destroy), finalize(()=>this.gatewayBusy.set(false))).subscribe({next:r=>this.gateway.set(r),error:()=>this.gateway.set({connected:false,message:'Cannot reach the assessment API. Check the backend and private gateway tunnel.'})});
  }
  protected notificationBusy = signal(false);
  protected notifications = signal<{enabled:boolean;configured:boolean;minimumSeverity:string;missing:string[];counts:{state:string;count:number}[]} | null>(null);
  protected checkNotifications() {
    this.notificationBusy.set(true);
    this.http.get<NonNullable<ReturnType<typeof this.notifications>>>('/api/notifications/status').pipe(takeUntilDestroyed(this.destroy),finalize(()=>this.notificationBusy.set(false))).subscribe({next:r=>this.notifications.set(r),error:e=>this.errors.set(apiErrors(e))});
  }
  private http = inject(HttpClient);
  private destroy = inject(DestroyRef);
  protected config = signal<Connections | null>(null);
  protected results = signal<Record<string, Result>>({});
  protected busy = signal('');
  protected errors = signal<string[]>([]);
  protected services = [
    {
      key: 'hexstrike',
      label: 'HexStrike AI',
      icon: 'HX',
      description: 'Tool orchestration running inside your Kali laboratory.',
    },
    {
      key: 'ollama',
      label: 'Local intelligence',
      icon: 'AI',
      description: 'Local model server for on-demand analysis of saved assessment results.',
    },
  ];
  constructor() {
    this.http
      .get<Connections>('/api/lab/connections')
      .pipe(takeUntilDestroyed())
      .subscribe({ next: (r) => this.config.set(r), error: (e) => this.errors.set(apiErrors(e)) });
  }
  protected url(key: string) {
    return key === 'hexstrike' ? this.config()?.hexStrikeUrl : this.config()?.ollamaUrl;
  }
  protected time(v: string) {
    return new Date(v).toLocaleString();
  }
  protected check(key: string) {
    if (this.busy()) return;
    this.busy.set(key);
    this.errors.set([]);
    this.http
      .post<Result>('/api/lab/connections/' + key + '/check', {})
      .pipe(
        takeUntilDestroyed(this.destroy),
        finalize(() => this.busy.set('')),
      )
      .subscribe({
        next: (r) => this.results.update((v) => ({ ...v, [key]: r })),
        error: (e) => this.errors.set(apiErrors(e)),
      });
  }
}
