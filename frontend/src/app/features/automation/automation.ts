import { InfoPopup } from '../../shared/components/detail-modal';
import { ImportedRules } from './imported-rules';
import { DatePipe, JsonPipe } from '@angular/common';
import { HttpClient } from '@angular/common/http';
import { Component, DestroyRef, inject, signal } from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { finalize, forkJoin } from 'rxjs';
import { Auth } from '../../core/services/auth';
import { apiErrors } from '../../core/services/api-errors';
import { utcTimestamp } from '../../core/services/incidents';
import { ErrorNotice } from '../../shared/components/error-notice';
interface Policy { id:string;mode:string;version:number;correlationMinutes:number;ownerId:number|null;effectiveFrom:string; }
interface Mapping { framework:string;control:string;status:string;rationale:string;reference:string; }
interface Rule {policy:Policy;definition:{name:string;channel:string;provider:string;eventId:number;canAutoPromote:boolean;falsePositives:string;reference:string;mappings:Mapping[]};counts:{outcome:string;count:number}[];}
interface RulePage {catalogRevision:string;lastCycleAt:string|null;error:string|null;rules:Rule[];owners:{id:number;fullName:string}[];}
interface Decision {id:number;alertId:number;incidentId:number|null;ruleId:string;policyVersion:number;machine:string;outcome:string;reason:string;policySnapshot:string;createdAt:string;}
interface Coverage {scope:string;mappings:Mapping[];gaps:string[];evidence:{enabled:boolean;retentionDays:number;lastCycleAt:string|null;storedEvents:number;decisions:number;channels:{channel:string;enabled:boolean;error:string|null;lastCheckedAt:string|null}[]};benchmark:{platform:string;profile:string;status:string;version:string|null;reference:string;reason:string};}
@Component({
  imports: [InfoPopup,ImportedRules,FormsModule,RouterLink,DatePipe,JsonPipe,ErrorNotice],
  template:`
    <div class="page-heading"><div><p class="eyebrow">DETECTION ENGINEERING</p><h1>Automation &amp; coverage</h1><p class="muted">Versioned rules, traceable decisions and evidence of control coverage.</p></div><button class="button secondary" [disabled]="busy()" (click)="load()">Refresh rules and evidence</button></div>
    <app-error-notice [messages]="errors()" />
    @if (notice()) {<p role="status">{{notice()}}</p>}
    @if (rules(); as page) {
      <section class="panel panel-padding"><h2>Incident automation</h2><p>Observe records decisions without changing alerts. AutoPromote creates or links an incident for eligible new alerts. Disabled stops this automation policy; Windows detection still creates alerts.</p><p class="muted">Changes apply only to alerts received after saving. Historical decisions are never replayed. Correlation groups the same host and rule version within a fixed incident window. Severity and priority are High for automated investigations.</p><p>Catalog {{page.catalogRevision}} &middot; Worker last completed: {{page.lastCycleAt ? (utc(page.lastCycleAt) | date:'medium') : 'Not yet reported'}}</p>@if(page.error){<p role="alert">{{page.error}}</p>}</section>
      @for(row of page.rules;track row.policy.id){
        <section class="panel panel-padding section-space"><div class="section-heading"><h2>{{row.definition.name}}</h2><span class="badge neutral">Policy v{{row.policy.version}}</span></div>
          <p><code>{{row.policy.id}}</code> &middot; Event {{row.definition.eventId}}</p><p class="muted">{{row.definition.channel}} / {{row.definition.provider}}</p>
          <p><a [href]="row.definition.reference" target="_blank" rel="noopener noreferrer">Microsoft event reference &nearr;</a></p><p><strong>Review context:</strong> {{row.definition.falsePositives}}</p>
          <form (ngSubmit)="save(row)"><div class="dashboard-controls">
            <div><label [for]="row.policy.id+'-mode'">Mode</label><select [id]="row.policy.id+'-mode'" name="mode" [(ngModel)]="row.policy.mode" [disabled]="!auth.hasRole('ADMIN') || busy()"><option>Disabled</option><option>Observe</option>@if(row.definition.canAutoPromote){<option>AutoPromote</option>}</select></div>
            <div><label [for]="row.policy.id+'-owner'">Incident owner</label><select [id]="row.policy.id+'-owner'" name="owner" [(ngModel)]="row.policy.ownerId" [disabled]="!auth.hasRole('ADMIN') || busy()"><option [ngValue]="null">Select an owner</option>@for(owner of page.owners;track owner.id){<option [ngValue]="owner.id">{{owner.fullName}}</option>}</select></div>
            <div><label [for]="row.policy.id+'-window'">Correlation window (minutes)</label><input type="number" min="5" max="1440" [id]="row.policy.id+'-window'" name="window" [(ngModel)]="row.policy.correlationMinutes" [disabled]="!auth.hasRole('ADMIN') || busy()" /></div>
            @if(auth.hasRole('ADMIN')){<button class="button" [disabled]="busy()">Save policy</button>}
          </div></form>
          <p class="muted small-text">Effective from {{utc(row.policy.effectiveFrom) | date:'medium'}}. AutoPromote requires an active owner. Inactive approvers/owners cause NeedsReview decisions.</p>
          @for(count of row.counts;track count.outcome){<span class="badge neutral">{{count.outcome}}: {{count.count}}</span>}
        </section>
      }
    }
    <app-imported-rules />
    @if(coverage();as c){
      <section class="panel panel-padding section-space"><h2>Standards coverage</h2><p>{{c.scope}}</p><p class="muted">Mappings indicate technical support, not certification or full compliance. These local rules are based on Microsoft event documentation; they are not imported Sigma rules.</p>
      <div class="table-scroll"><table><thead><tr><th>Framework / control</th><th>Status</th><th>Evidence boundary</th></tr></thead><tbody>@for(m of c.mappings;track m.framework){<tr><td><a [href]="m.reference" target="_blank" rel="noopener noreferrer">{{m.framework}}</a><br>{{m.control}}</td><td>{{m.status}}</td><td>{{m.rationale}}</td></tr>}</tbody></table></div>
      <p>{{c.evidence.storedEvents}} stored events &middot; {{c.evidence.decisions}} automation decisions &middot; Raw log retention: {{c.evidence.retentionDays}} days</p>
      <h3>Open gaps</h3><ul>@for(gap of c.gaps;track gap){<li>{{gap}}</li>}</ul>
      <h3>Required log channels</h3>@for(channel of c.evidence.channels;track channel.channel){<p>{{channel.channel}}: {{channel.error || (channel.enabled && channel.lastCheckedAt ? 'Readable at last collection check' : 'Not verified')}}</p>}
      <a routerLink="/windows-events">Inspect channel coverage &rarr;</a>
      <h3>CIS Windows 11 Benchmark</h3><p><strong>{{c.benchmark.status}}</strong> &middot; {{c.benchmark.profile}} &middot; Version: {{c.benchmark.version || 'Not selected'}}</p><p>{{c.benchmark.reason}}</p><a [href]="c.benchmark.reference" target="_blank" rel="noopener noreferrer">Official CIS benchmark catalog &nearr;</a>
      </section>
    }
    <section class="panel panel-padding section-space"><h2>Decision history</h2><p class="muted">Latest 50 per page. Refresh to fetch new decisions.</p><div class="table-scroll"><table><thead><tr><th>Time / rule</th><th>Outcome</th><th>Evidence</th></tr></thead><tbody>
    @for(d of decisions();track d.id){<tr><td>{{utc(d.createdAt) | date:'medium'}}<br>{{d.ruleId}} v{{d.policyVersion}}<br>{{d.machine}}</td><td>{{d.outcome}}<br>{{d.reason}}</td><td><a [routerLink]="['/alerts',d.alertId]">Alert #{{d.alertId}}</a>@if(d.incidentId){<br><a [routerLink]="['/incidents',d.incidentId]">Incident #{{d.incidentId}}</a>}<app-info-popup title="Policy and evidence snapshot"><span popupTrigger>Policy and evidence snapshot</span><pre>{{snapshot(d.policySnapshot) | json}}</pre></app-info-popup></td></tr>}@empty{<tr><td colspan="3">No automation decisions recorded. Existing ordinary logs are not converted into incidents.</td></tr>}
    </tbody></table></div><button class="button secondary" [disabled]="busy() || !hasMore()" (click)="older()">Older decisions</button></section>
  `,
})
export class AutomationPage {
  protected readonly auth=inject(Auth);private readonly http=inject(HttpClient);private readonly destroyRef=inject(DestroyRef);
  protected readonly rules=signal<RulePage|null>(null);protected readonly coverage=signal<Coverage|null>(null);
  protected readonly decisions=signal<Decision[]>([]);protected readonly hasMore=signal(false);protected readonly busy=signal(false);
  protected readonly errors=signal<string[]>([]);protected readonly notice=signal('');protected readonly utc=utcTimestamp;
  constructor(){this.load();}
  protected load(){if(this.busy())return;this.busy.set(true);this.errors.set([]);
    forkJoin({rules:this.http.get<RulePage>('/api/automation/rules'),coverage:this.http.get<Coverage>('/api/automation/coverage'),decisions:this.http.get<{items:Decision[];hasMore:boolean}>('/api/automation/decisions')})
    .pipe(takeUntilDestroyed(this.destroyRef),finalize(()=>this.busy.set(false))).subscribe({next:data=>{this.rules.set(data.rules);this.coverage.set(data.coverage);this.decisions.set(data.decisions.items);this.hasMore.set(data.decisions.hasMore);},error:e=>this.errors.set(apiErrors(e))});}
  protected save(row:Rule){if(this.busy())return;this.busy.set(true);this.errors.set([]);this.notice.set('');
    this.http.put<Policy>('/api/automation/rules/'+row.policy.id,row.policy).pipe(takeUntilDestroyed(this.destroyRef),finalize(()=>this.busy.set(false)))
    .subscribe({next:policy=>{row.policy=policy;this.notice.set('Policy saved. Applies to newly received alerts only.');},error:e=>this.errors.set(apiErrors(e))});}
  protected older(){if(this.busy()||!this.hasMore())return;this.busy.set(true);
    this.http.get<{items:Decision[];hasMore:boolean}>('/api/automation/decisions',{params:{before:this.decisions().at(-1)!.id}})
    .pipe(takeUntilDestroyed(this.destroyRef),finalize(()=>this.busy.set(false))).subscribe({next:d=>{this.decisions.set(d.items);this.hasMore.set(d.hasMore);},error:e=>this.errors.set(apiErrors(e))});}
  protected snapshot(value:string):unknown{try{return JSON.parse(value);}catch{return value;}}
}
