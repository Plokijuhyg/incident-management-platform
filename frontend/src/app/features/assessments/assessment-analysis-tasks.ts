import { Injectable, effect, inject, signal } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Subject, Subscription } from 'rxjs';
import { Auth } from '../../core/services/auth';
import { apiErrors } from '../../core/services/api-errors';
export interface Analysis {status:string;model:string;evidenceSha256:string;inputSha256:string;promptVersion:string;mode?:string;generatedAt:string;text:string|null;error:string|null;includedObservations:number;totalObservations:number;inputTruncated:boolean;outputTruncated:boolean;}

export interface AnalysisTask { id:string; label:string; busy:boolean; report:Analysis|null; errors:string[]; }
@Injectable({providedIn:'root'})
export class AssessmentAnalysisTasks {
 private http=inject(HttpClient);
 private auth=inject(Auth);
 private subscription?:Subscription;
 readonly task=signal<AnalysisTask|null>(null);
 readonly restore=new Subject<string>();
 constructor(){
  let owner=this.auth.user()?.id;
  effect(()=>{const current=this.auth.user()?.id;if(current!==owner){this.subscription?.unsubscribe();this.task.set(null);owner=current;}});
 }
 start(id:string,label:string,mode:'defensive'|'offensive'='defensive'){
  if(this.task()?.busy)return;
  this.task.set({id,label,busy:true,report:null,errors:[]});
  // This subscription belongs to the session, never to the evidence popup.
  this.subscription=this.http.post<Analysis>('/api/assessments/'+id+'/analysis',{mode}).subscribe({
   next:report=>this.task.set({id,label,busy:false,report,errors:[]}),
   error:error=>this.task.set({id,label,busy:false,report:null,errors:apiErrors(error)})
  });
 }
 dismiss(){if(!this.task()?.busy)this.task.set(null);}
}
