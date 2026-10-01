import { Component, DestroyRef, inject, input, output, signal } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { FormsModule } from '@angular/forms';
import { DatePipe } from '@angular/common';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { finalize } from 'rxjs';
import { apiErrors } from '../../core/services/api-errors';
import { ErrorNotice } from './error-notice';
interface Indicator {type:string;value:string;}
interface Report extends Indicator {status:string;malicious:number|null;total:number|null;categories:string[];checkedAt:string;expiresAt:string;message:string;}
interface State {configured:boolean;candidates:Indicator[];reports:Report[];}
@Component({selector:'app-intel-panel',imports:[FormsModule,DatePipe,ErrorNotice],template:`
<section class="panel panel-padding section-space"><h2>Threat intelligence &middot; VirusTotal</h2>
<p class="muted">Retrieve an existing reputation report for an indicator in this record. Results do not change severity or trigger a response action.</p>
<button class="button secondary" (click)="load()" [disabled]="busy()">Load indicators &amp; saved reports</button>
<app-error-notice [messages]="errors()" />
@if(state();as s){
 @if(!s.configured){<p class="notice">VirusTotal is not configured on the API host.</p>}
 @if(s.candidates.length){<label class="intel-select">Indicator<select [(ngModel)]="selected" (ngModelChange)="confirmed=false"><option value="">Select an indicator</option>@for(i of s.candidates;track i.type+':'+i.value;let n=$index){<option [value]="n">{{i.type}} &middot; {{i.value}}</option>}</select></label>
 <label class="intel-confirm"><input type="checkbox" [(ngModel)]="confirmed" /> I confirm sharing this indicator with VirusTotal. Review URLs for private tokens or sensitive paths.</label>
 <button class="button" (click)="lookup()" [disabled]="busy() || !s.configured || selected==='' || !confirmed">{{busy()?'Checking...':'Enrich selected indicator'}}</button>
 }@else{<p>No eligible public IP, domain, hash or URL found. Private addresses stay local. For an incident, link an indicator in the Indicators tab first.</p>}
 @for(r of s.reports;track r.type+':'+r.value){<article class="intel-report"><strong class="break-word">{{r.type}} &middot; {{r.value}}</strong><p><span class="badge neutral">{{r.status}}</span> @if(r.malicious!==null){<b>{{r.malicious}} / {{r.total}} malicious verdicts</b>}</p><p>{{r.message}}</p>@if(r.categories.length){<p>Categories: {{r.categories.join(', ')}}</p>}<small>Checked {{r.checkedAt|date:'medium'}} &middot; Cache expires {{r.expiresAt|date:'medium'}}</small></article>}
}
</section>`,styles:[`.intel-select{display:block;margin:16px 0}.intel-select select{display:block;width:100%;margin-top:6px}.intel-confirm{display:flex;gap:10px;align-items:center;margin:16px 0}.intel-confirm input{width:18px;height:18px;flex:none}.intel-report{border-top:1px solid #d6dce3;padding:16px 0;margin-top:16px}.intel-report .badge{margin-right:12px}`]})
export class IntelPanel {
 readonly enriched=output<void>();
 readonly kind=input.required<'alerts'|'incidents'>();readonly recordId=input.required<number>();
 private http=inject(HttpClient);private destroy=inject(DestroyRef);
 protected state=signal<State|null>(null);protected busy=signal(false);protected errors=signal<string[]>([]);protected selected='';protected confirmed=false;
 private endpoint(){return '/api/'+this.kind()+'/'+this.recordId()+'/enrichment';}
 protected load(){if(this.busy())return;this.busy.set(true);this.errors.set([]);this.http.get<State>(this.endpoint()).pipe(takeUntilDestroyed(this.destroy),finalize(()=>this.busy.set(false))).subscribe({next:r=>{this.state.set(r);this.selected='';this.confirmed=false;},error:e=>this.errors.set(apiErrors(e))});}
 protected lookup(){const i=this.state()?.candidates[Number(this.selected)];if(!i||this.selected===''||!this.confirmed||this.busy())return;this.busy.set(true);this.errors.set([]);
 this.http.post<Report>(this.endpoint(),{...i,confirmed:true}).pipe(takeUntilDestroyed(this.destroy),finalize(()=>this.busy.set(false))).subscribe({next:r=>{this.state.update(s=>s?{...s,reports:[r,...s.reports.filter(x=>x.type!==r.type||x.value!==r.value)]}:s);this.confirmed=false;this.enriched.emit();},error:e=>this.errors.set(apiErrors(e))});}
}
