import { InfoPopup } from '../../shared/components/detail-modal';
import { JsonPipe } from '@angular/common';
import { HttpClient } from '@angular/common/http';
import { Component, DestroyRef, inject, signal } from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { FormsModule } from '@angular/forms';
import { finalize } from 'rxjs';
import { Auth } from '../../core/services/auth';
import { apiErrors } from '../../core/services/api-errors';
import { ErrorNotice } from '../../shared/components/error-notice';
interface ImportedRule {
  id:number;externalRuleId:string;title:string;severity:string;referenceTag:string|null;enabled:boolean;updatedAt:string;
  policy?:{mode:string;ownerId:number|null;correlationMinutes:number}; mode?:string;ownerId?:number|null;correlationMinutes?:number;preview?:{scanned:number;matched:number;invalid:number;scope:string}; unsupportedReason:string|null;definition:{logsource:unknown;detection:unknown;tags:string[];sourceFile:string;sourceSha256:string;description:string;falsepositives:string[]};
}
interface RuleResult {total:number;page:number;items:ImportedRule[];owners?:{id:number;fullName:string}[];}
@Component({
  selector:'app-imported-rules',imports: [InfoPopup,FormsModule,JsonPipe,ErrorNotice],
  template:`<section class="panel panel-padding section-space">
    <h2>Imported Sigma rules</h2>
    <p>Review imported definitions before enabling detection. Choose alerts only, or assign an owner and automatically open incidents from matching new events.</p>
    <p class="muted">A supported definition still needs its actual log channel and fields. Importing a rule does not install Sysmon or enable Windows audit policies.</p>
    <form (ngSubmit)="load(1)" class="search"><label for="sigma-search">Search title, external ID or first tag</label><div><input id="sigma-search" name="search" [(ngModel)]="search" /><button class="button" [disabled]="busy()">Load rules</button></div></form>
    <app-error-notice [messages]="errors()" />
    @if(notice()){<p role="status">{{notice()}}</p>}
    @if(result();as page){
      <p>{{page.total}} definitions &middot; Page {{page.page}}</p>
      @for(rule of page.items;track rule.id){
        <app-info-popup title="{{rule.title}} {{rule.severity}} {{rule.enabled?'Enabled':'Disabled'}}" (opened)="clearReview(rule.id)" (closed)="clearReview(rule.id)"><span popupTrigger><strong>{{rule.title}}</strong> <span class="badge neutral">{{rule.severity}}</span> <span>{{rule.enabled?'Enabled':'Disabled'}}</span></span>
          <p><code>{{rule.externalRuleId}}</code></p>
          <p>{{rule.unsupportedReason || 'Condition and source mapping supported. Verify that required fields are actually collected.'}}</p>
          <p>Published tags: {{rule.definition.tags.join(', ') || 'None'}}</p>
          <p>Source: {{rule.definition.sourceFile}}</p><p>{{rule.definition.description}}</p>
          <h3>Published false-positive context</h3><ul>@for(context of rule.definition.falsepositives;track $index){<li>{{context}}</li>}@empty{<li>No context provided in the source definition. Review locally before enabling.</li>}</ul>
          <h3>Log source</h3><pre>{{rule.definition.logsource|json}}</pre>
          <h3>Detection conditions</h3><pre>{{rule.definition.detection|json}}</pre>
          @if(!rule.unsupportedReason){<button class="button secondary" [disabled]="busy()" (click)="preview(rule)">Preview latest 1,000 events</button>}
          @if(rule.preview;as preview){<p role="status">{{preview.matched}} matches / {{preview.scanned}} checked; {{preview.invalid}} could not be evaluated. {{preview.scope}}</p>}
          @if(auth.hasRole('ADMIN')){
            <div class="policy-fields"><label>When a new event matches<select [(ngModel)]="rule.mode"><option value="Observe">Create alert for review</option><option value="AutoPromote">Create alert and incident</option></select></label>
            @if(rule.mode==='AutoPromote'){<label>Incident owner<select [(ngModel)]="rule.ownerId"><option [ngValue]="null">Select owner</option>@for(owner of page.owners || [];track owner.id){<option [ngValue]="owner.id">{{owner.fullName}}</option>}</select></label><label>Group same host/rule within (minutes)<input type="number" min="5" max="1440" [(ngModel)]="rule.correlationMinutes" /></label>}
            </div>
            @if(!rule.unsupportedReason){<label class="confirm"><input type="checkbox" [checked]="reviewed()===rule.id" (change)="reviewed.set($any($event.target).checked?rule.id:null)" /> I reviewed the conditions, source fields and expected false positives.</label>}
            <button class="button secondary" [disabled]="busy() || (!rule.enabled && (!!rule.unsupportedReason || reviewed()!==rule.id))" (click)="save(rule,!rule.enabled)">{{rule.enabled?'Disable detection':'Enable reviewed rule'}}</button>
            @if(rule.enabled){<button class="button" [disabled]="busy() || reviewed()!==rule.id || (rule.mode==='AutoPromote' && !rule.ownerId)" (click)="save(rule,true)">Save reviewed policy</button>}
          }
        </app-info-popup>
      }@empty{<p>No imported rules found.</p>}
      <div class="pages"><button class="button secondary" [disabled]="busy()||page.page<=1" (click)="load(page.page-1)">Previous</button><button class="button secondary" [disabled]="busy()||page.page*25>=page.total" (click)="load(page.page+1)">Next</button></div>
    }
  </section>`,
  styles:[`.policy-fields{display:flex;flex-wrap:wrap;gap:16px;margin:16px 0}.policy-fields label{flex:1;min-width:200px}.policy-fields select,.policy-fields input{display:block;width:100%;margin-top:6px}.search{max-width:650px}.search div,.pages{display:flex;gap:12px;margin:12px 0}.search input{flex:1;min-width:0}.rule{padding:16px 0;border-top:1px solid #d6dce3}.rule summary{cursor:pointer;line-height:1.8}.rule summary span{margin-left:12px}.rule pre{max-height:320px;overflow:auto;background:#f5f7fa;padding:14px;font-size:13px}.confirm{display:flex;align-items:center;gap:10px;margin:16px 0}.confirm input{width:17px;height:17px;flex:none}`],
})
export class ImportedRules {
  protected readonly auth=inject(Auth);private readonly http=inject(HttpClient);private readonly destroyRef=inject(DestroyRef);
  protected readonly result=signal<RuleResult|null>(null);protected readonly busy=signal(false);protected readonly errors=signal<string[]>([]);
  protected readonly reviewed=signal<number|null>(null);protected readonly notice=signal('');protected search='';
  protected clearReview(id:number){if(this.reviewed()===id)this.reviewed.set(null);}
  protected load(page:number){if(this.busy())return;this.busy.set(true);this.errors.set([]);this.reviewed.set(null);
    this.http.get<RuleResult>('/api/detection-rules',{params:{search:this.search,page}}).pipe(takeUntilDestroyed(this.destroyRef),finalize(()=>this.busy.set(false)))
      .subscribe({next:r=>{r.items.forEach(rule=>{rule.mode=rule.policy?.mode==='AutoPromote'?'AutoPromote':'Observe';rule.ownerId=rule.policy?.ownerId??null;rule.correlationMinutes=rule.policy?.correlationMinutes??60;});this.result.set(r);},error:e=>this.errors.set(apiErrors(e))});}
  protected preview(rule:ImportedRule){if(this.busy())return;this.busy.set(true);this.errors.set([]);
    this.http.get<NonNullable<ImportedRule['preview']>>('/api/detection-rules/'+rule.id+'/preview').pipe(takeUntilDestroyed(this.destroyRef),finalize(()=>this.busy.set(false))).subscribe({next:r=>rule.preview=r,error:e=>this.errors.set(apiErrors(e))});}
  protected save(rule:ImportedRule,enabled:boolean){if(this.busy())return;this.busy.set(true);this.errors.set([]);this.notice.set('');
    this.http.put<{id:number;enabled:boolean;updatedAt:string}>('/api/detection-rules/'+rule.id+'/enabled',{enabled,updatedAt:rule.updatedAt,confirmed:this.reviewed()===rule.id,mode:rule.mode||'Observe',ownerId:rule.ownerId??null,correlationMinutes:rule.correlationMinutes??60})
      .pipe(takeUntilDestroyed(this.destroyRef),finalize(()=>this.busy.set(false))).subscribe({next:r=>{rule.enabled=r.enabled;rule.updatedAt=r.updatedAt;this.reviewed.set(null);this.notice.set(r.enabled?'Rule enabled for newly ingested events.':'Rule disabled. Existing evidence is retained.');},error:e=>this.errors.set(apiErrors(e))});}
}
