import { Component, DestroyRef, inject, signal } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { FormsModule } from '@angular/forms';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { finalize, timer } from 'rxjs';
import { ErrorNotice } from '../../shared/components/error-notice';
import { InfoPopup } from '../../shared/components/detail-modal';
import { apiErrors } from '../../core/services/api-errors';
import { utcTimestamp } from '../../core/services/incidents';

interface Step {
  step: number;
  kind: 'tool' | 'final';
  modelSeconds?: number;
  tool?: string;
  args?: string;
  status?: string;
  toolSeconds?: number;
  output?: string;
  text?: string;
}
interface Run {
  id: string;
  task: string;
  targetName: string;
  targetIp: string;
  maxSteps?: number;
  status: string;
  model: string;
  summary?: string | null;
  error?: string | null;
  createdAt: string;
  startedAt?: string | null;
  finishedAt?: string | null;
  transcript?: Step[] | null;
}

// AI Orchestrator panel: the local LLM selects which bounded, reviewed tools to run for a
// natural-language task. Exploitation is never exposed here; runs are slow on CPU and stream
// their transcript as each step completes.
@Component({
  selector: 'app-ai-orchestrator',
  imports: [FormsModule, ErrorNotice, InfoPopup],
  template: `
    <section class="panel panel-padding">
      <div class="section-title">
        <span class="step-number">AI</span>
        <div>
          <h2>AI Orchestrator <span class="badge">local LLM</span></h2>
          <p>
            Describe a task in plain English. The local model decides which <strong>reviewed
            recon/scan tools</strong> to run against your approved target and runs them through the
            same bounded gateway. No exploitation tools are available here &mdash; exploitation stays
            operator-run. Each step is slow on CPU; the transcript updates as it goes.
          </p>
        </div>
      </div>

      <label for="orch-ip">Lab target IP</label>
      <input id="orch-ip" name="orchIp" [(ngModel)]="targetIp" placeholder="e.g. 192.168.50.11" inputmode="decimal" autocomplete="off" />
      @if (targetIp && !privateIp(targetIp)) { <p class="field-error">Enter a private lab IP (10.x, 172.16&ndash;31.x or 192.168.x).</p> }

      <label for="orch-task">Task</label>
      <textarea id="orch-task" name="orchTask" rows="3" [(ngModel)]="task"
        placeholder="e.g. Scan and enumerate this host, then report the most likely exploitable vulnerability."></textarea>

      <div class="endpoint-fields">
        <div><label for="orch-steps">Max steps</label><input id="orch-steps" type="number" name="orchSteps" [(ngModel)]="maxSteps" min="1" max="10" /></div>
        <div><label for="orch-port">Web port</label><input id="orch-port" type="number" name="orchPort" [(ngModel)]="webPort" min="1" max="65535" /></div>
        <label class="inline-check"><input type="checkbox" name="orchHttps" [(ngModel)]="webHttps" /> Use HTTPS</label>
      </div>

      <button class="button start-button" (click)="run()" [disabled]="busy() || !canRun()">
        {{ busy() ? 'Submitting…' : 'Run AI orchestration' }}
      </button>
      <p class="run-hint">The model and tools run locally on the Kali laptop. A full run can take several minutes per step.</p>
      <app-error-notice [messages]="errors()" />

      @if (active(); as r) {
        <div class="orch-run">
          <p>
            <span class="status-pill" [class.status-ok]="r.status === 'Completed'" [class.status-error]="r.status === 'Failed'" [class.status-active]="r.status === 'Running' || r.status === 'Pending'">{{ r.status }}</span>
            <code>{{ r.targetIp }}</code> &middot; model <code>{{ r.model || '—' }}</code>
          </p>
          @if (r.error) { <p class="field-error">{{ r.error }}</p> }
          @for (step of r.transcript || []; track $index) {
            @if (step.kind === 'tool') {
              <p><strong>Step {{ step.step }}</strong> &middot; decided in {{ step.modelSeconds }}s &rarr;
                <code>{{ step.tool }}</code>
                <span class="badge" [class.danger]="step.status === 'error' || step.status === 'rejected'">{{ step.status }}</span>
                @if (step.toolSeconds != null) { <small class="muted">ran {{ step.toolSeconds }}s</small> }
              </p>
              @if (step.output) {
                <app-info-popup title="Tool output"><span popupTrigger>Tool output</span><pre class="raw-output">{{ step.output }}</pre></app-info-popup>
              }
            } @else {
              <p><strong>Final summary</strong> &middot; produced in {{ step.modelSeconds }}s</p>
              <pre class="raw-output">{{ step.text }}</pre>
            }
          }
          @if (r.status === 'Running' || r.status === 'Pending') { <p class="muted" aria-live="polite">Working… this updates automatically.</p> }
        </div>
      }

      @if (runs().length) {
        <h3>Recent orchestrations</h3>
        <div class="table-scroll">
          <table>
            <thead><tr><th>When</th><th>Target</th><th>Task</th><th>Status</th><th></th></tr></thead>
            <tbody>
              @for (r of runs(); track r.id) {
                <tr>
                  <td>{{ date(r.createdAt) }}</td>
                  <td>{{ r.targetIp }}</td>
                  <td class="break-word">{{ r.task }}</td>
                  <td><span class="status-pill" [class.status-ok]="r.status === 'Completed'" [class.status-error]="r.status === 'Failed'" [class.status-active]="r.status === 'Running' || r.status === 'Pending'">{{ r.status }}</span></td>
                  <td><button class="link-button" (click)="open(r.id)">View</button></td>
                </tr>
              }
            </tbody>
          </table>
        </div>
      }
    </section>
  `,
})
export class AiOrchestrator {
  private http = inject(HttpClient);
  private destroy = inject(DestroyRef);
  protected runs = signal<Run[]>([]);
  protected active = signal<Run | null>(null);
  protected errors = signal<string[]>([]);
  protected busy = signal(false);
  protected targetIp = '';
  protected task = '';
  protected maxSteps = 6;
  protected webPort = 80;
  protected webHttps = false;
  private polling = false;

  constructor() {
    this.list();
    timer(0, 5000).pipe(takeUntilDestroyed()).subscribe(() => {
      if (document.hidden) return;
      this.list();
      const a = this.active();
      if (a && (a.status === 'Running' || a.status === 'Pending')) this.open(a.id, true);
    });
  }

  protected date(v: string) { return new Date(utcTimestamp(v)).toLocaleString(); }
  protected privateIp(value: string) {
    const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec((value || '').trim());
    if (!m) return false;
    const b = m.slice(1).map(Number);
    if (b.some((n) => n > 255)) return false;
    return b[0] === 10 || (b[0] === 172 && b[1] >= 16 && b[1] <= 31) || (b[0] === 192 && b[1] === 168);
  }
  protected canRun() { return this.privateIp(this.targetIp) && this.task.trim().length > 0; }

  private list() {
    this.http.get<Run[]>('/api/assessments/orchestrations').pipe(takeUntilDestroyed(this.destroy))
      .subscribe({ next: (r) => this.runs.set(r), error: () => {} });
  }
  protected open(id: string, silent = false) {
    if (silent && this.polling) return;
    this.polling = true;
    this.http.get<Run>('/api/assessments/orchestrations/' + id).pipe(
      takeUntilDestroyed(this.destroy),
      finalize(() => (this.polling = false)),
    ).subscribe({ next: (r) => this.active.set(r), error: (e) => { if (!silent) this.errors.set(apiErrors(e)); } });
  }
  protected run() {
    if (this.busy() || !this.canRun()) return;
    this.busy.set(true);
    this.errors.set([]);
    this.http.post<Run>('/api/assessments/orchestrations', {
      task: this.task.trim(), targetIp: this.targetIp.trim(),
      maxSteps: this.maxSteps, webPort: this.webPort, webHttps: this.webHttps, webPath: '/',
    }).pipe(takeUntilDestroyed(this.destroy), finalize(() => this.busy.set(false)))
      .subscribe({ next: (r) => { this.active.set(r); this.list(); }, error: (e) => this.errors.set(apiErrors(e)) });
  }
}
