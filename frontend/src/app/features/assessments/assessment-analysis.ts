import { Component, computed, inject, input, signal } from '@angular/core';
import { DatePipe } from '@angular/common';
import { HttpClient } from '@angular/common/http';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { AssessmentAnalysisTasks, Analysis } from './assessment-analysis-tasks';
import { apiErrors } from '../../core/services/api-errors';
@Component({selector:'app-assessment-analysis',imports:[DatePipe],template:`
 <section class="analysis-panel" aria-labelledby="analysis-heading">
  <h3 id="analysis-heading">Local model analysis</h3>
  <p class="muted">Review assistance from the local model. Generated text may be incorrect; verify it against the original evidence. Recommendations do not execute actions or change scanner findings.</p>
  <div class="mode-switch" role="group" aria-label="Analysis mode">
   <button type="button" class="button secondary small" [class.active]="mode()==='defensive'" (click)="setMode('defensive')">Defensive brief</button>
   <button type="button" class="button secondary small" [class.active]="mode()==='offensive'" (click)="setMode('offensive')">Exploitation walkthrough (lab)</button>
  </div>
  @if(mode()==='offensive'){<p class="muted small-text">Explains how each finding would be exploited on an authorized, isolated lab target (for example Metasploitable) for learning, with the detection and remediation that follow. Use it only on targets you are authorized to test.</p>}
  @if(config();as c){<p>Model: <strong>{{c.model || 'Not configured'}}</strong></p>@if(!c.configured){<p class="notice">Enable Ollama and configure its model on the API host before requesting analysis.</p>}}
  @if(models().length>1){<p class="model-switch"><label for="an-model">Model: </label><select id="an-model" [disabled]="busy()" (change)="model.set($any($event.target).value)">@for(m of models();track m){<option [value]="m" [selected]="m===model()">{{m}}</option>}</select></p>}
  <button class="button secondary" type="button" [disabled]="busy() || !eligible() || config()?.configured!==true" (click)="analyze()">{{busy() ? 'Analyzing saved results...' : report()?.status==='Completed' && !stale() ? 'View saved ' + modeLabel() : 'Analyze: ' + modeLabel()}}</button>
  @if(!eligible()){<p class="muted">Available after a completed or partial scan has stored normalized evidence.</p>}
  @if(busy()){<p role="status">The first request may load the model. Allow up to three minutes. You can minimize or close this window and continue working; analysis stays running.</p>}
  @for(error of errors();track error){<p class="notice" role="alert">{{error}}</p>}
  @if(report();as r){
    <div class="analysis-meta"><span class="badge neutral">{{r.status}}</span><span>{{r.model}}</span><span>{{r.generatedAt | date:'medium'}}</span></div>
    @if(stale()){<p class="notice">This analysis references older evidence or model settings. Generate a new analysis before relying on it.</p>}
    @if(r.error){<p class="notice">{{r.error}}</p>}
    @if(r.text){<p class="muted">{{r.includedObservations}} / {{r.totalObservations}} observations included.</p><pre class="analysis-text">{{r.text}}</pre>}
    @if(r.inputTruncated){<p class="notice">Only a bounded subset of observations was sent. Some fields were shortened or observations omitted.</p>}
    @if(r.outputTruncated){<p class="notice">The model reached its response limit; this analysis may be incomplete.</p>}
    <small class="analysis-hash">Evidence SHA-256: {{r.evidenceSha256}}</small>
  }
 </section>`,styles:[`.analysis-panel{border-top:1px solid #d7e0ea;margin-top:24px;padding-top:18px}.mode-switch{display:flex;gap:8px;flex-wrap:wrap;margin:12px 0}.mode-switch .active{outline:2px solid var(--teal,#1d949c);outline-offset:1px;font-weight:700}.analysis-meta{display:flex;gap:12px;flex-wrap:wrap;margin:16px 0}.analysis-text{white-space:pre-wrap;overflow-wrap:anywhere;font:inherit;line-height:1.65;background:#f5f8fc;border:1px solid #d7e0ea;border-radius:6px;padding:18px;max-height:440px;overflow:auto}.analysis-hash{display:block;overflow-wrap:anywhere;color:#59677a}`]})
export class AssessmentAnalysisPanel {
 assessment=input.required<{id:string;status:string;targetName?:string;analysisJson?:string|null;evidenceSha256?:string|null;observationsJson?:string|null}>();
 private http=inject(HttpClient);private tasks=inject(AssessmentAnalysisTasks);
 protected busy=computed(()=>this.tasks.task()?.busy===true);private configErrors=signal<string[]>([]);protected errors=computed(()=>[...this.configErrors(),...(this.tasks.task()?.id===this.assessment().id?this.tasks.task()?.errors||[]:[])]);protected config=signal<{configured:boolean;model:string;promptVersion?:string;defensivePromptVersion?:string;offensivePromptVersion?:string}|null>(null);
 protected mode=signal<'defensive'|'offensive'>('defensive');
 protected models=signal<string[]>([]);protected model=signal<string>('');
 protected modeLabel=computed(()=>this.mode()==='offensive'?'exploitation walkthrough':'defensive brief');
 private expectedVersion=computed(()=>{const c=this.config();return this.mode()==='offensive'?c?.offensivePromptVersion:(c?.defensivePromptVersion??c?.promptVersion);});

 protected eligible=computed(()=>['Completed','Partial'].includes(this.assessment().status)&&!!this.assessment().observationsJson&&!!this.assessment().evidenceSha256);
 protected report=computed(()=>{const a=this.assessment(),received=this.tasks.task();if(received?.id===a.id && received.report)return received.report;try{const v=JSON.parse(a.analysisJson||'null');if(!v)return null;return Object.fromEntries(Object.entries(v).map(([k,v])=>[k[0].toLowerCase()+k.slice(1),v])) as unknown as Analysis;}catch{return null;}});
 protected stale=computed(()=>{const r=this.report();const expected=this.expectedVersion();const chosen=this.model()||this.config()?.model;return !!r&&(r.evidenceSha256!==this.assessment().evidenceSha256||!!chosen&&r.model!==chosen||(r.mode??'defensive')!==this.mode()||!!expected&&r.promptVersion!==expected);});
 constructor(){
  this.http.get<{configured:boolean;model:string;promptVersion?:string;defensivePromptVersion?:string;offensivePromptVersion?:string}>('/api/assessments/analysis/status').pipe(takeUntilDestroyed()).subscribe({next:c=>this.config.set(c),error:e=>this.configErrors.set(apiErrors(e))});
  this.http.get<{models:string[];defaultModel:string}>('/api/assessments/analysis/models').pipe(takeUntilDestroyed()).subscribe({next:r=>{this.models.set(r.models||[]);if(!this.model())this.model.set(r.defaultModel||'');},error:()=>{}});
 }
 protected setMode(mode:'defensive'|'offensive'){if(!this.busy())this.mode.set(mode);}
 protected analyze(){if(this.busy()||!this.eligible())return;const a=this.assessment();this.tasks.start(a.id,a.targetName||'Assessment',this.mode(),this.model());}
}
