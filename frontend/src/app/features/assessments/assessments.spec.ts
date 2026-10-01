import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { AssessmentsPage } from './assessments';
import { afterEach, beforeEach, expect, it } from 'vitest';
// jsdom does not implement native dialog methods; real focus/Escape behavior is checked in Chromium.
const showModalDescriptor=Object.getOwnPropertyDescriptor(HTMLDialogElement.prototype,'showModal');
const closeDescriptor=Object.getOwnPropertyDescriptor(HTMLDialogElement.prototype,'close');
beforeEach(()=>{Object.defineProperty(HTMLDialogElement.prototype,'showModal',{configurable:true,value:function(this:HTMLDialogElement){this.setAttribute('open','');}});Object.defineProperty(HTMLDialogElement.prototype,'close',{configurable:true,value:function(this:HTMLDialogElement){this.removeAttribute('open');}});});

afterEach(() => {TestBed.resetTestingModule();for(const [name,descriptor] of [['showModal',showModalDescriptor],['close',closeDescriptor]] as const){if(descriptor)Object.defineProperty(HTMLDialogElement.prototype,name,descriptor);else Reflect.deleteProperty(HTMLDialogElement.prototype,name);}});
it('shows live tools, blocks unavailable tools and submits only the selected scope with confirmation', () => {
 TestBed.configureTestingModule({providers:[provideHttpClient(),provideHttpClientTesting()]});
 const fixture=TestBed.createComponent(AssessmentsPage);
 const http=TestBed.inject(HttpTestingController);
 http.expectOne('/api/assessments/targets').flush([{id:'lab',name:'Lab',ip:'192.168.207.129'}]);
 http.expectOne('/api/assessments/capabilities').flush({connected:true,message:'Live',profiles:[],manifestId:'manifest',tools:[
  {name:'nikto_scan',category:'Web',tier:'intrusive',available:true,description:'Bounded web checks',reason:''},
  {name:'new_cloud_tool',category:'Cloud',tier:'unclassified',available:false,description:'Live tool',reason:'Scope not configured'}
 ]});
 const page=fixture.componentInstance as unknown as {target:string;confirmed:boolean;toggleCategory(c:string):void;toggleTool(n:string):void;start():void};
 page.target='lab';page.toggleCategory('Cloud');fixture.detectChanges();
 fixture.nativeElement.querySelector('.tool-group .popup-trigger').click();fixture.detectChanges();
 const disabled=fixture.nativeElement.querySelector('.scan-tool input') as HTMLInputElement;
 expect(disabled.disabled).toBe(true);
 expect(fixture.nativeElement.textContent).toContain('new_cloud_tool');
 fixture.nativeElement.querySelector('dialog header button').click();fixture.detectChanges();
 page.toggleCategory('Cloud');page.toggleCategory('Web');page.toggleTool('nikto_scan');page.start();
 http.expectNone('/api/assessments/scan');
 page.confirmed=true;page.start();
 const request=http.expectOne('/api/assessments/scan');
 expect(request.request.body).toEqual({targetId:'lab',categories:['Web'],selectedTools:['nikto_scan'],manifestId:'manifest',confirmed:true,webPort:80,webHttps:false,webPath:'/'});
 request.flush({id:'job',status:'Pending'});
 http.match('/api/assessments').forEach(r=>r.flush([]));
 http.match('/api/assessments/job').forEach(r=>r.flush({id:'job',status:'Pending'}));
 page.toggleTool('nikto_scan');expect(page.confirmed).toBe(false);
 fixture.destroy();http.verify();
});
