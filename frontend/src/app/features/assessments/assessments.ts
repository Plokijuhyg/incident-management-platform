import { AssessmentAnalysisTasks } from './assessment-analysis-tasks';
import { ActivatedRoute } from '@angular/router';
import { AssessmentAnalysisPanel } from './assessment-analysis';
import { InfoPopup } from '../../shared/components/detail-modal';
import { DetailModal } from '../../shared/components/detail-modal';
import { ToolCatalog } from './tool-catalog';
import { Component, DestroyRef, inject, signal } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { FormsModule } from '@angular/forms';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { finalize, forkJoin, timer } from 'rxjs';
import { ErrorNotice } from '../../shared/components/error-notice';
import { apiErrors } from '../../core/services/api-errors';
import { parseObservations, filterObservations, severities } from './assessment-results';
import { utcTimestamp } from '../../core/services/incidents';
interface Target {
  id: string;
  name: string;
  ip: string;
}
interface ScanTool { name: string; category: string | null; tier: string; available: boolean; reason: string; description: string; }
interface Capability {
  tools?: ScanTool[];
  manifestId?: string;
  connected: boolean;
  message: string;
  profiles: { id: string; name: string }[];
}
interface Assessment {
  id: string;
  targetName: string;
  targetIp: string;
  profile: string;
  status: string;
  requestedAt: string;
  error: string | null;
  requestJson?: string | null;
  rawResponse?: string | null;
  evidenceSha256?: string | null;
  observationsJson?: string | null;
  analysisJson?: string | null;
}
@Component({
  imports: [AssessmentAnalysisPanel,InfoPopup,DetailModal,FormsModule, ErrorNotice, ToolCatalog],
  styleUrl: './assessments.css',
  template: `
    <div class="page-heading">
      <div>
        <p class="eyebrow">AUTHORIZED SECURITY LAB</p>
        <h1>Security Assessments</h1>
        <p class="muted">Review real tool evidence from your approved Kali laboratory.</p>
      </div>
      <button class="button secondary" (click)="discover()" [disabled]="discovering()">
        Check gateway
      </button>
    </div>
    <app-error-notice [messages]="errors()" />
    <app-tool-catalog />
    <form class="assessment-builder" (ngSubmit)="start()">
      <div class="builder-main">
        <section class="panel setup-section">
          <div class="section-title"><span class="step-number">1</span><div><h2>Choose a target</h2><p>Enter the IP of your approved private lab device (for example your Metasploitable VM), or pick a saved one.</p></div></div>
          <label for="assessment-ip">Lab target IP</label>
          <input id="assessment-ip" name="targetIp" [(ngModel)]="targetIp" (ngModelChange)="onIpChange()" placeholder="e.g. 192.168.207.129" inputmode="decimal" autocomplete="off" />
          @if (targetIp && !privateIp(targetIp)) { <p class="field-error">Enter a private lab IP (10.x, 172.16&ndash;31.x or 192.168.x). Public addresses are not allowed.</p> }
          @if (targets().length) {
            <label for="assessment-target">Or choose a saved target</label>
            <select id="assessment-target" name="target" [(ngModel)]="target" (ngModelChange)="onTargetSelect()">
              <option value="">Select a saved target</option>
              @for (t of targets(); track t.id) { <option [value]="t.id">{{ t.name }} &middot; {{ t.ip }}</option> }
            </select>
          }
        </section>
        <section class="panel setup-section">
          <div class="section-title"><span class="step-number">2</span><div><h2>Choose your checks</h2><p>Select a category, then choose the tools to run.</p></div></div>
          <div class="category-grid">
            @for (category of categories; track category) {
              <fieldset class="category-card" [class.chosen]="selectedCategories.includes(category)">
                <legend><label><input type="checkbox" [checked]="selectedCategories.includes(category)" (change)="toggleCategory(category)" /> {{ category }}</label></legend>
                <p>{{ categoryDescription(category) }}</p><span>{{ capability()?.connected ? readyTools(category).length + ' available' : 'Connect gateway to check' }}</span>
              </fieldset>
            }
          </div>
          @if (!selectedCategories.length) { <div class="selection-empty">Choose a category above to see its tools.</div> }
          @for (category of selectedCategories; track category) {
            <section class="tool-group" [attr.aria-label]="category + ' tools'">
              <div class="tool-group-heading"><h3>{{ category }} tools</h3><button type="button" class="button secondary small" [disabled]="!readyTools(category).length" (click)="selectAvailable(category)">Select available tools</button></div>
              <div class="tool-grid">
                @for (tool of readyTools(category); track tool.name) {
                  <label class="scan-tool" [class.checked]="selectedTools.includes(tool.name)">
                    <input type="checkbox" [checked]="selectedTools.includes(tool.name)" (change)="toggleTool(tool.name)" />
                    <span class="tool-copy"><span class="tool-title">{{ toolLabel(tool.name) }}</span><span class="tool-tier" [class.caution]="tool.tier !== 'safe'">{{ tool.tier === 'safe' ? 'Standard check' : 'Confirmation required' }}</span><small>{{ tool.description }}</small><code>{{ tool.name }}</code></span>
                  </label>
                }
              </div>
              @if (!readyTools(category).length) { <p class="notice">No checks are ready for this category on the current setup.</p> }
              @if (unavailableTools(category).length) {
                <app-info-popup title="{{ unavailableTools(category).length }} unavailable tools &mdash; view reasons"><span popupTrigger>{{ unavailableTools(category).length }} unavailable tools &mdash; view reasons</span>
                  @for (tool of unavailableTools(category); track tool.name) {
                    <label class="scan-tool unavailable"><input type="checkbox" disabled /><span class="tool-copy"><strong>{{ toolLabel(tool.name) }}</strong><small>{{ tool.reason }}</small><code>{{ tool.name }}</code></span></label>
                  }
                </app-info-popup>
              }
            </section>
          }
        </section>
        @if (selectedCategories.includes('Web') || selectedCategories.includes('API')) {
          <section class="panel setup-section">
            <div class="section-title"><span class="step-number">3</span><div><h2>Web &amp; API endpoint</h2><p>Use the port and path of the service on your selected device.</p></div></div>
            <div class="endpoint-fields">
              <div><label for="web-port">Port</label><input id="web-port" type="number" name="webPort" [(ngModel)]="webPort" (ngModelChange)="confirmed = false" min="1" max="65535" /></div>
              <div><label for="web-path">Path</label><input id="web-path" name="webPath" [(ngModel)]="webPath" (ngModelChange)="confirmed = false" placeholder="/ or /graphql" /></div>
              <label class="inline-check"><input type="checkbox" name="https" [(ngModel)]="webHttps" (ngModelChange)="confirmed = false" /> Use HTTPS</label>
            </div>
            <p class="endpoint-preview">{{ endpointPreview() }}</p>
          </section>
        }
      </div>
      <aside class="panel run-summary">
        <div class="connection-status" [class.connected]="capability()?.connected"><span></span>{{ capability()?.connected ? 'Gateway connected' : 'Gateway unavailable' }}</div>
        <h2>Review &amp; run</h2>
        <dl><dt>Target</dt><dd>{{ targetLabel() }}</dd><dt>Selected tools</dt><dd class="selection-count">{{ selectedTools.length }}</dd></dl>
        @if (selectedTools.length) { <div class="selected-names">@for (name of selectedTools; track name) { <span>{{ toolLabel(name) }}</span> }</div> }
        @if (needsConfirmation()) { <label class="confirmation-box"><input type="checkbox" name="confirm" [(ngModel)]="confirmed" /><span>I confirm the selected intrusive/destructive checks on this approved lab target.</span></label> }
        <button class="button start-button" [disabled]="busy() || !canStart()">{{ busy() ? 'Submitting...' : 'Start assessment' }}</button>
        <p class="run-hint" aria-live="polite">{{ startHint() }}</p>
        <app-info-popup title="Connection details"><span popupTrigger>Connection details</span><p>{{ capability()?.message || 'Checking configuration...' }}</p></app-info-popup>
      </aside>
    </form>
    <section class="panel panel-padding">
      <h2>Execution history</h2>
      <p class="muted small-text">
        Latest 100 assessments. Status refreshes every 5 seconds; no progress percentage is
        estimated.
      </p>
      @if (!rows().length) {
        <div class="empty-state">No assessments have been requested.</div>
      } @else {
        <div class="table-scroll">
          <table>
            <thead>
              <tr>
                <th>Requested</th>
                <th>Target</th>
                <th>Assessment</th>
                <th>Status</th>
                <th>Evidence</th>
              </tr>
            </thead>
            <tbody>
              @for (r of rows(); track r.id) {
                <tr>
                  <td>{{ date(r.requestedAt) }}</td>
                  <td>
                    {{ r.targetName }}<br /><small>{{ r.targetIp }}</small>
                  </td>
                  <td>{{ profileName(r.profile) }}</td>
                  <td>
                    <span class="status-pill" [class.status-ok]="r.status === 'Completed'" [class.status-error]="r.status === 'Failed'" [class.status-active]="r.status === 'Running'">{{ r.status }}</span>
                    @if (r.error) {
                      <p class="field-error">{{ r.error }}</p>
                    }
                  </td>
                  <td>
                    <button class="link-button" (click)="open(r.id)">Inspect assessment</button>
                    @if (r.status === 'Pending') {
                      <button
                        class="button secondary small"
                        (click)="cancel(r.id)"
                        [disabled]="busy()"
                      >
                        Cancel queued job
                      </button>
                    }
                  </td>
                </tr>
              }
            </tbody>
          </table>
        </div>
      }
    </section>
    @if (selected(); as r) {
      <app-detail-modal title="Assessment evidence" [minimizable]="true" (minimized)="close()" (closed)="close()"><section>
        <div class="action-toolbar">
          <h2>Assessment evidence</h2>
          
        </div>
        <p>
          <code>{{ r.id }}</code> &middot; {{ r.status }}
        </p>
        @if (r.error) {
          <p class="notice">{{ r.error }}</p>
        }
        @if (r.requestJson) { <app-info-popup title="Requested categories and tools"><span popupTrigger>Requested categories and tools</span><pre class="raw-output">{{ r.requestJson }}</pre></app-info-popup> }
        <h3>Findings and service observations</h3>
        <p class="muted">Severity is supplied by the check or template, not inferred from an open port. Nikto observations require severity triage.</p>
        @if (coverage(r); as c) {
          <p class="notice">{{ c }}</p>
        }
        @for (step of steps(r); track $index) {
          <p><strong>{{ step['tool'] }}</strong> {{ step['endpoint'] }} &middot; {{ step['status'] }} {{ step['reason'] }} {{ step['error'] }}</p><p class="muted">{{ step['interpretation'] }}</p>
          @if (step['evidence']) { <app-info-popup title="{{ step['tool'] }} output"><span popupTrigger>{{ step['tool'] }} output</span><pre class="raw-output">{{ step['evidence'] }}</pre></app-info-popup> }
        }
        <p aria-live="polite"><strong>{{ findingCount(r) }}</strong> scanner findings &middot;
          <strong>{{ observations(r).length - findingCount(r) }}</strong> service observations.
          Counts describe this assessment only.</p>
        <div class="filter-bar">
          <div><label for="result-kind">Result type</label><select id="result-kind" [(ngModel)]="resultKind">
            <option value="all">All results</option><option value="findings">Scanner findings</option><option value="services">Service observations</option>
          </select></div>
          <div><label for="result-severity">Severity</label><select id="result-severity" [(ngModel)]="resultSeverity">
            <option value="">All severities</option>@for (severity of severityOptions; track severity) { <option [value]="severity">{{ severity }}</option> }
          </select></div>
          <div><label for="result-search">Search results</label><input id="result-search" [(ngModel)]="resultSearch" placeholder="CVE, service, tool or endpoint" /></div>
        </div>
        @if (visibleObservations(r).length) {
          <div class="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>Endpoint / Port</th>
                  <th>Tool / Protocol</th>
                  <th>Finding / Service</th>
                  <th>Evidence / Details</th>
                  <th>Classification</th>
                </tr>
              </thead>
              <tbody>
                @for (o of visibleObservations(r); track $index) {
                  <tr>
                    <td>{{ o['endpoint'] || o['port'] }}</td>
                    <td>{{ o['tool'] || o['protocol'] }}</td>
                    <td>{{ o['title'] || o['service'] }}</td>
                    <td>{{ o['product'] }} {{ o['version'] }} {{ o['cve'] }}
                      @if (o['kind'] === 'Finding') {
                        <app-info-popup title="Review evidence"><span popupTrigger>Review evidence</span><p>{{ o['confidence'] }}</p><p>{{ o['severityBasis'] }}</p><pre class="raw-output">{{ o['evidence'] }}</pre></app-info-popup>
                      }
                    </td>
                    <td><span class="badge" [class.danger]="o['severity'] === 'High' || o['severity'] === 'Critical'">{{ o['severity'] }}</span></td>
                  </tr>
                }
              </tbody>
            </table>
          </div>
        } @else {
          <p class="muted">
            {{ observations(r).length ? 'No results match these filters.' : 'No parsed observations available. An empty or failed assessment is not proof that the target is secure.' }}
          </p>
        }
        @if (r.rawResponse) {
          <app-info-popup title="Original gateway response and tool evidence"><span popupTrigger>Original gateway response and tool evidence</span>
            <pre class="raw-output">{{ r.rawResponse }}</pre>
          </app-info-popup>
          <p class="muted small-text break-word">Stored response SHA-256: {{ r.evidenceSha256 }}</p>
        } @else {
          <p class="muted">No raw response received yet.</p>
        }
        <app-assessment-analysis [assessment]="r" />
      </section></app-detail-modal>
    }
  `,
})
export class AssessmentsPage {
  private http = inject(HttpClient);
  private destroy = inject(DestroyRef);
  protected targets = signal<Target[]>([]);
  protected capability = signal<Capability | null>(null);
  protected rows = signal<Assessment[]>([]);
  protected selected = signal<Assessment | null>(null);
  protected errors = signal<string[]>([]);
  protected busy = signal(false);
  protected discovering = signal(false);
  private refreshing = false;
  protected target = '';
  protected targetIp = '';
  protected profile = '';
  protected categories = ['Network', 'Web', 'Cloud', 'API'];
  protected selectedCategories: string[] = [];
  protected selectedTools: string[] = [];
  protected confirmed = false;
  protected webPath = '/';
  protected webPort = 80;
  protected webHttps = false;
  protected categoryTools(category: string) { return (this.capability()?.tools || []).filter(t => t.category === category); }
  protected readyTools(category: string) { return this.categoryTools(category).filter(t => t.available); }
  protected unavailableTools(category: string) { return this.categoryTools(category).filter(t => !t.available); }
  protected toolLabel(name: string) { return name.replaceAll('_', ' ').replace(/\b(scan|analyze|probe)$/, '').trim(); }
  protected categoryDescription(category: string) { return ({ Network: 'Ports, services & SMB', Web: 'Websites & application checks', Cloud: 'Cloud accounts & clusters', API: 'Endpoints & API schemas' } as Record<string,string>)[category]; }
  protected privateIp(value: string) { const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec((value || '').trim()); if (!m) return false; const b = m.slice(1).map(Number); if (b.some(n => n > 255)) return false; return b[0] === 10 || (b[0] === 172 && b[1] >= 16 && b[1] <= 31) || (b[0] === 192 && b[1] === 168); }
  protected resolvedIp() { const value = this.targets().find(t => t.id === this.target); if (value) return value.ip; return this.privateIp(this.targetIp) ? this.targetIp.trim() : ''; }
  protected hasTarget() { return !!this.target || this.privateIp(this.targetIp); }
  protected onIpChange() { if (this.targetIp) this.target = ''; this.confirmed = false; }
  protected onTargetSelect() { if (this.target) this.targetIp = ''; this.confirmed = false; }
  protected targetLabel() { const value = this.targets().find(t => t.id === this.target); if (value) return value.name + ' · ' + value.ip; return this.privateIp(this.targetIp) ? 'Lab target · ' + this.targetIp.trim() : 'No target selected'; }
  protected endpointPreview() { const ip = this.resolvedIp(); return ip ? (this.webHttps ? 'https://' : 'http://') + ip + ':' + this.webPort + this.webPath : 'Enter a lab IP to preview the endpoint.'; }
  protected canStart() { return this.hasTarget() && !!this.capability()?.connected && this.selectedTools.length > 0 && this.selectedCategories.every(c => this.readyTools(c).some(t => this.selectedTools.includes(t.name))) && (!this.needsConfirmation() || this.confirmed); }
  protected startHint() {
    if (!this.capability()?.connected) return 'Connect the gateway before starting.';
    if (!this.hasTarget()) return 'Enter a private lab IP or choose a saved target first.';
    if (!this.selectedTools.length) return 'Select at least one available tool.';
    if (this.selectedCategories.some(c => !this.readyTools(c).some(t => this.selectedTools.includes(t.name)))) return 'Choose tools for each category, or uncheck empty categories.';
    if (this.needsConfirmation() && !this.confirmed) return 'Review and confirm the selected checks.';
    return 'Only your selected tools will run. Results appear below.';
  }
  protected toggleCategory(category: string) {
    this.selectedCategories = this.selectedCategories.includes(category) ? this.selectedCategories.filter(c => c !== category) : [...this.selectedCategories, category];
    this.selectedTools = this.selectedTools.filter(n => (this.capability()?.tools || []).some(t => t.name === n && this.selectedCategories.includes(t.category || '')));
    this.confirmed = false;
  }
  protected selectAvailable(category: string) { this.selectedTools = [...new Set([...this.selectedTools, ...this.categoryTools(category).filter(t => t.available).map(t => t.name)])]; this.confirmed = false; }
  protected toggleTool(name: string) { this.selectedTools = this.selectedTools.includes(name) ? this.selectedTools.filter(t => t !== name) : [...this.selectedTools, name]; this.confirmed = false; }
  protected needsConfirmation() { return (this.capability()?.tools || []).some(t => this.selectedTools.includes(t.name) && t.tier !== 'safe'); }

  constructor() {
    inject(AssessmentAnalysisTasks).restore.pipe(takeUntilDestroyed()).subscribe(id=>this.open(id));
    const route=inject(ActivatedRoute,{optional:true});
    route?.queryParamMap.pipe(takeUntilDestroyed()).subscribe(params=>{const id=params.get('assessment');if(id)this.open(id);});
    this.discover();
    timer(30000, 30000).pipe(takeUntilDestroyed()).subscribe(() => { if (!document.hidden && !this.capability()?.connected && !this.busy()) this.discover(); });
    timer(0, 5000)
      .pipe(takeUntilDestroyed())
      .subscribe(() => {
        if (!document.hidden) this.refresh();
      });
  }
  protected date(v: string) {
    return new Date(utcTimestamp(v)).toLocaleString();
  }
  protected observations(r: Assessment): Record<string, unknown>[] {
    return parseObservations(r.observationsJson);
  }
  protected severityOptions = severities;
  protected resultKind = 'all';
  protected resultSeverity = '';
  protected resultSearch = '';
  private detailRequest = 0;
  protected findingCount(r: Assessment) { return this.observations(r).filter(o => o['kind'] === 'Finding').length; }
  protected visibleObservations(r: Assessment) { return filterObservations(this.observations(r), this.resultKind, this.resultSeverity, this.resultSearch); }
  protected profileName(id: string) { return id === 'selected-tools' ? 'Selected MCP tools' : id === 'vulnerability-checks' ? 'SMB and web vulnerability checks' : id === 'tcp-services' ? 'TCP service inventory' : id; }
  protected close() { this.detailRequest++; this.selected.set(null); }
  protected steps(r: Assessment): Record<string, unknown>[] {
    try { const value = JSON.parse(r.rawResponse || '{}').steps; return Array.isArray(value) ? value : []; } catch { return []; }
  }
  protected coverage(r: Assessment): string {
    try { return JSON.parse(r.rawResponse || '{}').coverage || ''; } catch { return ''; }
  }
  protected discover() {
    if (this.discovering()) return;
    this.discovering.set(true);
    forkJoin({
      targets: this.http.get<Target[]>('/api/assessments/targets'),
      capability: this.http.get<Capability>('/api/assessments/capabilities'),
    })
      .pipe(
        takeUntilDestroyed(this.destroy),
        finalize(() => this.discovering.set(false)),
      )
      .subscribe({
        next: (r) => {
          this.targets.set(r.targets);
          this.capability.set(r.capability);
          this.profile = ''; this.selectedTools = []; this.selectedCategories = []; this.confirmed = false;
        },
        error: (e) => { this.capability.set({connected:false,message:'Gateway check failed. Verify the private tunnel and retry.',profiles:[],tools:[]}); this.errors.set(apiErrors(e)); },
      });
  }
  private refresh() {
    if (this.refreshing) return;
    this.refreshing = true;
    this.http
      .get<Assessment[]>('/api/assessments')
      .pipe(
        takeUntilDestroyed(this.destroy),
        finalize(() => (this.refreshing = false)),
      )
      .subscribe({
        next: (r) => {
          this.rows.set(r);
          if (this.selected()) this.open(this.selected()!.id);
        },
        error: (e) => this.errors.set(apiErrors(e)),
      });
  }
  protected open(id: string) {
    const request = ++this.detailRequest;
    this.http
      .get<Assessment>('/api/assessments/' + id)
      .pipe(takeUntilDestroyed(this.destroy))
      .subscribe({
        next: (r) => { if (request === this.detailRequest) this.selected.set(r); },
        error: (e) => this.errors.set(apiErrors(e)),
      });
  }
  protected start() {
    if (this.busy() || !this.canStart()) return;
    this.busy.set(true);
    this.http
      .post<Assessment>('/api/assessments/scan', { targetId: this.target, targetIp: this.targetIp.trim(), categories: this.selectedCategories, selectedTools: this.selectedTools, manifestId: this.capability()?.manifestId, confirmed: this.confirmed, webPort: this.webPort, webHttps: this.webHttps, webPath: this.webPath })
      .pipe(
        takeUntilDestroyed(this.destroy),
        finalize(() => this.busy.set(false)),
      )
      .subscribe({
        next: (r) => {
          this.selected.set(r);
          this.errors.set([]);
          this.refresh();
        },
        error: (e) => this.errors.set(apiErrors(e)),
      });
  }
  protected cancel(id: string) {
    if (this.busy()) return;
    this.busy.set(true);
    this.http
      .post('/api/assessments/' + id + '/cancel', {})
      .pipe(
        takeUntilDestroyed(this.destroy),
        finalize(() => this.busy.set(false)),
      )
      .subscribe({ next: () => this.refresh(), error: (e) => this.errors.set(apiErrors(e)) });
  }
}
