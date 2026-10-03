import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { afterEach, expect, it } from 'vitest';
import { AssessmentAnalysisPanel } from './assessment-analysis';
import { AssessmentAnalysisTasks } from './assessment-analysis-tasks';
import { Auth } from '../../core/services/auth';

afterEach(()=>TestBed.resetTestingModule());
function setup(){
 TestBed.configureTestingModule({providers:[provideHttpClient(),provideHttpClientTesting()]});
 const auth=TestBed.inject(Auth);
 auth.user.set({id:1,email:'analyst@example.test',fullName:'Analyst',roles:['ADMIN']});
 const tasks=TestBed.inject(AssessmentAnalysisTasks), http=TestBed.inject(HttpTestingController);
 TestBed.tick();
 return {auth,tasks,http};
}
it('keeps a request alive after popup destruction and restores the completed report without another POST',()=>{
 const {tasks,http}=setup();
 const panel=TestBed.createComponent(AssessmentAnalysisPanel);
 panel.componentRef.setInput('assessment',{id:'a',status:'Completed',observationsJson:'[]',evidenceSha256:'abc'});
 http.expectOne('/api/assessments/analysis/status').flush({configured:true,model:'local',promptVersion:'v2'});
 panel.detectChanges();
 (Array.from(panel.nativeElement.querySelectorAll('button')) as HTMLButtonElement[]).find(b=>b.textContent!.includes('Analyze'))!.click();
 const pending=http.expectOne('/api/assessments/a/analysis');
 panel.destroy();
 expect(pending.cancelled).toBe(false);
 tasks.start('a','Same assessment');
 http.expectNone('/api/assessments/a/analysis');
 expect(tasks.task()?.busy).toBe(true);
 pending.flush({status:'Completed',model:'local',promptVersion:'v2',evidenceSha256:'abc',text:'Finished in background',generatedAt:new Date().toISOString()});
 expect(tasks.task()?.busy).toBe(false);
 const restored=TestBed.createComponent(AssessmentAnalysisPanel);
 restored.componentRef.setInput('assessment',{id:'a',status:'Completed',observationsJson:'[]',evidenceSha256:'abc'});
 http.expectOne('/api/assessments/analysis/status').flush({configured:true,model:'local',promptVersion:'v2'});
 restored.detectChanges();
 expect(restored.nativeElement.textContent).toContain('Finished in background');
 restored.destroy();http.verify();
});
it('retains failure status for review and lets the user retry',()=>{
 const {tasks,http}=setup();tasks.start('a','Lab');
 http.expectOne('/api/assessments/a/analysis').flush({title:'Unavailable'},{status:503,statusText:'Unavailable'});
 expect(tasks.task()?.busy).toBe(false);expect(tasks.task()?.errors.length).toBeGreaterThan(0);
 tasks.start('a','Lab');http.expectOne('/api/assessments/a/analysis').flush({status:'Completed'});
 expect(tasks.task()?.errors).toEqual([]);http.verify();
});
it('cancels and clears private analysis state when the signed-in user changes',()=>{
 const {auth,tasks,http}=setup();tasks.start('a','Lab');
 const pending=http.expectOne('/api/assessments/a/analysis');
 auth.clear();TestBed.tick();expect(pending.cancelled).toBe(true);expect(tasks.task()).toBeNull();http.verify();
});
