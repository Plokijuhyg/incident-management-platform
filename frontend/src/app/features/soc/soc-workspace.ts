import { DetailModal } from '../../shared/components/detail-modal';
import {DatePipe,DecimalPipe} from '@angular/common';
import {HttpClient,HttpParams} from '@angular/common/http';
import {Component,DestroyRef,inject,signal} from '@angular/core';
import {takeUntilDestroyed} from '@angular/core/rxjs-interop';
import {FormsModule} from '@angular/forms';
import {ActivatedRoute,RouterLink} from '@angular/router';
import {Subscription,finalize,timer} from 'rxjs';
import {apiErrors} from '../../core/services/api-errors';
import {utcTimestamp} from '../../core/services/incidents';
import {categories,statuses} from '../../core/models/api';
import {ErrorNotice} from '../../shared/components/error-notice';
import {SeverityBadge} from '../../shared/components/severity-badge';
interface IncidentRow {id:number;incidentNumber:string;title:string;severity:number;status:number;category:number;createdAt:string;owner:string|null;}
interface Technique {id:number;techniqueId:string;name:string;tactic:string;isSubTechnique:boolean;url:string|null;}
interface EventRow {id:number;receivedAt:string;machine:string;provider:string;channel:string;eventId:number;level:number;message:string;rawXml?:string;}
interface Task {id:number;incidentId:number;incidentNumber:string;actionType:number;description:string;targetValue:string|null;status:number;result:string|null;owner:string;}
interface Snapshot {
 classification?:{totalEvents:number;taggedEvents:number;unmappedEvents:number};alertCounts?:{techniqueId:string;count:number}[];
 telemetry?:{events:number;alerts:number;enabledRules:number;assets:number};
 observedAt:string;total:number;start:string;bucketMinutes:number;width:number;hasMore:boolean;
 categories:{label:string;count:number;high:number;medium:number}[];
 topHosts:{id:number;name:string;ip:string|null;count:number;high:number}[];
 topIncidents:{title:string;count:number}[];latest:IncidentRow[];
 timeline:{bucket:number;severity:number;count:number}[];
 techniques:Technique[];counts:{id:number;count:number}[];devices:{id:number;name:string;tactic:string;count:number}[];
 series:{index:number;count:number}[];items:EventRow[];
}
@Component({
 styleUrl:'./soc-workspace.css',
 imports: [DetailModal,FormsModule,RouterLink,DatePipe,DecimalPipe,ErrorNotice,SeverityBadge],
 template:`
 <div class="page-heading"><div><p class="eyebrow">SECURITY OPERATIONS WORKSPACE</p><h1>{{title}}</h1></div><div class="button-row"><a class="button secondary" routerLink="/overview">Overview</a><a class="button secondary" routerLink="/incidents">Incident list</a><a class="button secondary" routerLink="/attack-matrix">MITRE ATT&amp;CK</a><a class="button secondary" routerLink="/tasks">Response tasks</a></div></div>
 @if(view!=='resources'){
 <form class="soc-toolbar" (ngSubmit)="apply()">
 @if(view==='analytics'){<div><label for="soc-minutes">Event receive time</label><select id="soc-minutes" name="minutes" [(ngModel)]="minutes"><option [ngValue]="15">Last 15 minutes</option><option [ngValue]="60">Last hour</option><option [ngValue]="1440">Last 24 hours</option><option [ngValue]="10080">Last 7 days</option></select></div><div><label for="soc-search">Provider, host or message</label><input id="soc-search" name="search" [(ngModel)]="search" maxlength="200" /></div><div><label for="soc-channel">Exact channel (optional)</label><input id="soc-channel" name="channel" [(ngModel)]="channel" maxlength="255" /></div>}
 @else if(view==='tasks'){<div><label for="soc-status">Task status</label><select id="soc-status" name="status" [(ngModel)]="taskStatus"><option value="">All statuses</option>@for(label of taskStatuses;track label;let i=$index){<option [value]="i">{{label}}</option>}</select></div>}
 @else{<div><label for="soc-hours">Incident creation time</label><select id="soc-hours" name="hours" [(ngModel)]="hours"><option [ngValue]="2">Last 2 hours</option><option [ngValue]="24">Last 24 hours</option><option [ngValue]="168">Last 7 days</option><option [ngValue]="720">Last 30 days</option><option [ngValue]="2160">Last 90 days</option></select></div>
 @if(view==='overview'){<label><input type="checkbox" name="active" [(ngModel)]="activeOnly" /> Open incidents only</label>}}
 @if(view==='analytics'){<div class="event-query"><label for="event-query">Event query</label><input id="event-query" name="query" [(ngModel)]="query" maxlength="2000" placeholder='eventId = 4625 AND machine = "PCJAWAD"' /><small>AND / OR / NOT, parentheses; = != &gt; &gt;= &lt; &lt;=; ~ contains. Fields: eventId, level, id, machine, provider, channel, message.</small></div>}
 <button class="button secondary" [disabled]="busy()">Run / apply</button><button class="button secondary" type="button" (click)="live.set(!live())">{{live()?'Pause live refresh':'Resume live refresh'}}</button>
 </form><p class="muted small-text">{{live()?'Refresh every 15 seconds while visible.':'Live refresh paused.'}} Filters apply when you run the query. @if(refreshed()){Last updated {{refreshed() | date:'mediumTime'}}.}</p>}
 <app-error-notice [messages]="errors()" /> @if(errors().length && refreshed()){<p class="muted">Previously loaded results are retained and may be stale. Run the query again to retry.</p>}
 @if(busy()&&!data()&&!tasks()){<p role="status">Loading workspace...</p>}
 @if(data();as d){
 @if(view==='overview'){
 @if(d.telemetry;as s){<div class="stat-grid spotlight-stats"><article class="stat-card"><span>Collected events</span><strong>{{s.events|number}}</strong><a routerLink="/analytics">Explore logs</a></article><article class="stat-card"><span>Detection alerts</span><strong>{{s.alerts|number}}</strong><a routerLink="/alerts">Review alerts</a></article><article class="stat-card"><span>Enabled Sigma rules</span><strong>{{s.enabledRules}}</strong><a routerLink="/automation">Review detection policies</a></article><article class="stat-card"><span>Assets</span><strong>{{s.assets}}</strong><a routerLink="/assets">Source inventory</a></article></div>}
 @if(d.total===0){<p class="notice">No incidents in this range. Check enabled rules and their promotion mode in Automation; normal events are retained without being labelled incidents.</p>}
 <h2>Incidents by category <span class="badge neutral">{{d.total | number}} incidents in range</span></h2>
 <div class="soc-tiles">@for(c of d.categories;track c.label){<article class="soc-tile"><h3>{{c.label}}</h3><div class="tile-body"><strong>{{c.count}}</strong><p><span style="color:#bf3522">High / critical: {{c.high}}</span> &middot; Medium: {{c.medium}}</p></div></article>}@empty{<div class="panel panel-padding">No incidents created in this range. Windows logs remain available in Analytics.</div>}</div>
 <section class="panel panel-padding"><h2>Incident trend by severity</h2><p class="muted small-text">{{d.bucketMinutes}}-minute buckets, based on creation time. Red: critical/high; amber: medium; green: low.</p>
 <svg class="soc-chart" viewBox="0 0 900 180" role="img" aria-label="Incident creation trend by severity"><line x1="10" x2="890" y1="160" y2="160" stroke="#aaa" />@for(bar of incidentBars(d);track bar.key){<rect [attr.x]="bar.x" [attr.y]="bar.y" [attr.width]="bar.width" [attr.height]="bar.height" [style.fill]="colors[bar.severity]"><title>{{bar.count}} {{severityNames[bar.severity]}} incidents</title></rect>}</svg>
 </section>
 <h2>Top impacted hosts</h2><div class="soc-tiles">@for(host of d.topHosts;track host.id){<article class="soc-tile" [class.danger]="host.high>0"><h3><a [routerLink]="['/assets',host.id]" style="color:inherit">{{host.name}}</a></h3><div class="tile-body"><strong>{{host.count}}</strong> linked incidents<p>{{host.ip||'IP not recorded'}}</p><small>{{host.high}} high / critical incidents</small></div></article>}@empty{<p class="muted">No asset associations in this range. Link affected assets from an incident investigation.</p>}</div>
 <h2>Top incident titles</h2><div class="soc-tiles">@for(group of d.topIncidents;track group.title){<article class="soc-tile"><h3>{{group.title}}</h3><div class="tile-body"><strong>{{group.count}}</strong> incidents</div></article>}@empty{<p class="muted">No incident groups yet.</p>}</div>
 <section class="panel"><div class="panel-heading"><h2>Latest incidents (up to 50)</h2><a routerLink="/incidents">All incidents &rarr;</a></div><div class="table-scroll"><table><thead><tr><th>Severity</th><th>Created</th><th>Incident</th><th>Category</th><th>Status</th><th>Owner</th><th>Action</th></tr></thead><tbody>@for(row of d.latest;track row.id){<tr><td><app-severity [value]="row.severity" /></td><td>{{utc(row.createdAt)|date:'short'}}</td><td>{{row.title}}</td><td>{{categories[row.category]}}</td><td>{{statuses[row.status]}}</td><td>{{row.owner||'Unassigned'}}</td><td><a [routerLink]="['/incidents',row.id]">Investigate {{row.incidentNumber}}</a></td></tr>}@empty{<tr><td colspan="7">No incidents in the selected range.</td></tr>}</tbody></table></div></section>
 }
 @if(view==='attacks'){
 @if(d.classification;as c){<p class="notice">{{c.totalEvents|number}} events in range: {{c.taggedEvents|number}} have published Sigma technique references; {{c.unmappedEvents|number}} remain unclassified. Unclassified does not mean benign or malicious. MITRE tactics are not severity levels.</p>}

 <div class="soc-toolbar"><div><label for="technique-search">Search technique</label><input id="technique-search" [(ngModel)]="techniqueSearch" /></div><label><input type="checkbox" [(ngModel)]="observedOnly" /> Linked techniques only</label><label><input type="checkbox" [(ngModel)]="includeSubs" /> Include sub-techniques</label></div>
 <p class="muted">Coverage reflects explicit incident-to-technique associations in the loaded reference catalog. An unlinked technique is not proof of detection coverage. Highlighted cells have linked incidents in the selected range.</p>
 <section class="panel attack-coverage" aria-labelledby="coverage-heading">
   <div class="panel-heading"><div><p class="eyebrow">TACTICS &amp; TECHNIQUES</p><h2 id="coverage-heading">ATT&amp;CK coverage matrix</h2></div><span class="badge neutral">{{catalogue(d).length}} techniques shown</span></div>
   <div class="coverage-legend"><span><i class="legend-dot incident"></i>Linked incidents</span><span><i class="legend-dot alert"></i>Matched alerts only</span><span><i class="legend-dot empty"></i>No linked evidence</span><small>Colors indicate recorded evidence, not severity or guaranteed detection coverage.</small></div>
   <div class="coverage-scroll" tabindex="0" role="region" aria-label="MITRE tactic coverage table; scroll horizontally for more tactics">
     <table class="coverage-matrix" [style.min-width.px]="tactics(d).length*185"><thead><tr>@for(tactic of tactics(d);track tactic){<th scope="col"><span>{{tactic}}</span><small>{{filteredTechniques(d,tactic).length}} techniques</small></th>}</tr></thead>
       <tbody><tr>@for(tactic of tactics(d);track tactic){<td>
         @for(t of filteredTechniques(d,tactic);track t.id){
           <button type="button" class="coverage-cell" [class.has-incidents]="count(d,t.id)>0" [class.has-alerts]="count(d,t.id)===0&&alertCount(d,t.techniqueId)>0" [class.is-selected]="selectedTechnique()?.id===t.id" [attr.aria-pressed]="selectedTechnique()?.id===t.id" (click)="selectTechnique(t)">
             <span class="coverage-id">{{t.techniqueId}}</span><strong>{{t.name}}</strong>
             <span class="coverage-evidence">{{count(d,t.id)}} incidents &middot; {{alertCount(d,t.techniqueId)}} alerts</span>
           </button>
         }@empty{<p class="coverage-empty">No techniques match this filter.</p>}
       </td>}</tr></tbody>
     </table>
   </div>
   <p class="coverage-hint">Select a technique to review its linked incidents in a popup. Scroll sideways to explore all tactics.</p>
 </section>
 <section class="panel"><div class="panel-heading"><h2>Device / tactic coverage</h2></div><div class="table-scroll"><table><thead><tr><th>Device</th>@for(t of tactics(d);track t){<th>{{t}}</th>}</tr></thead><tbody>@for(host of hosts(d);track host.id){<tr><td><a [routerLink]="['/assets',host.id]">{{host.name}}</a></td>@for(t of tactics(d);track t){<td><span class="badge" [class.neutral]="deviceCount(d,host.id,t)===0" [class.coverage-count]="deviceCount(d,host.id,t)>0">{{deviceCount(d,host.id,t) || '-'}}</span></td>}</tr>}@empty{<tr><td>No incidents have both asset and MITRE associations in this range.</td></tr>}</tbody></table></div></section>
 <section class="panel"><div class="panel-heading"><h2>Technique catalogue</h2></div><div class="table-scroll"><table><thead><tr><th>Technique</th><th>Name</th><th>Tactic</th><th>Linked incidents</th><th>Matched alerts</th><th>Details</th></tr></thead><tbody>@for(t of catalogue(d);track t.id){<tr><td><button class="link-button" (click)="selectTechnique(t)">{{t.techniqueId}}</button></td><td>{{t.name}}</td><td>{{t.tactic}}</td><td>{{count(d,t.id)}}</td><td>{{alertCount(d,t.techniqueId)}}</td><td><a [routerLink]="['/attack-matrix',t.techniqueId]">Open reference</a></td></tr>}@empty{<tr><td colspan="6">No techniques match your filters.</td></tr>}</tbody></table></div></section>
 @if(selectedTechnique();as t){<app-detail-modal title="Technique coverage" (closed)="selectedTechnique.set(null); linked.set([])"><section><h2>{{t.techniqueId}} &middot; {{t.name}}</h2><a [routerLink]="['/attack-matrix',t.techniqueId]">Open technique details &rarr;</a><p class="muted">Latest 100 linked incidents in the selected range.</p><div class="table-scroll"><table><thead><tr><th>Incident</th><th>Title</th><th>Severity</th><th>Status</th></tr></thead><tbody>@for(row of linked();track row.id){<tr><td><a [routerLink]="['/incidents',row.id]">{{row.incidentNumber}}</a></td><td>{{row.title}}</td><td><app-severity [value]="row.severity" /></td><td>{{statuses[row.status]}}</td></tr>}@empty{<tr><td colspan="4">No linked incidents loaded.</td></tr>}</tbody></table></div></section></app-detail-modal>}
 }
 @if(view==='analytics'){
 <section class="panel panel-padding"><h2>Raw events &middot; {{d.total|number}} matched</h2><p class="muted">{{utc(d.start)|date:'short'}} to {{utc(d.observedAt)|date:'short'}} &middot; {{d.width}}-minute buckets &middot; Windows event receive time</p>
 <svg class="soc-chart" viewBox="0 0 900 180" role="img" aria-label="Matching events by receive time"><line x1="10" x2="890" y1="160" y2="160" stroke="#aaa" />@for(row of d.series;track row.index){<rect [attr.x]="10+row.index*880/buckets(d)" [attr.y]="160-row.count/eventMax(d)*145" [attr.width]="Math.max(1,880/buckets(d)-2)" [attr.height]="row.count/eventMax(d)*145"><title>{{row.count}} matching events</title></rect>}</svg></section>
 <section class="panel"><div class="panel-heading"><h2>Event results (100 per page)</h2><div class="button-row"><button class="button secondary" (click)="apply()">Latest</button><button class="button secondary" [disabled]="!d.hasMore||busy()" (click)="olderEvents()">Older events</button></div></div><div class="table-scroll"><table><thead><tr><th>Received</th><th>Host</th><th>Channel / provider</th><th>Event ID</th><th>Message preview</th><th>Action</th></tr></thead><tbody>@for(row of d.items;track row.id){<tr><td>{{utc(row.receivedAt)|date:'short'}}</td><td>{{row.machine}}</td><td>{{row.channel}}<br><small>{{row.provider}}</small></td><td>{{row.eventId}}</td><td style="max-width:480px;overflow-wrap:anywhere">{{row.message}}</td><td><button class="button secondary small" (click)="inspect(row.id)">Raw event</button></td></tr>}@empty{<tr><td colspan="6">No logs match this query.</td></tr>}</tbody></table></div></section>
 @if(event();as e){<app-detail-modal title="Raw event details" (closed)="event.set(null)"><section id="raw-event-details" class="soc-details"><h2>Event {{e.eventId}} &middot; {{e.provider}}</h2><h3>Full message</h3><pre>{{e.message}}</pre><h3>Original XML</h3><pre>{{e.rawXml}}</pre></section></app-detail-modal>}
 }
 }
 @if(view==='tasks'){ @if(tasks();as page){<section class="panel"><div class="panel-heading"><h2>Response actions &middot; {{page.total}} tasks</h2><span>Page {{taskPage}}</span><div class="button-row"><button class="button secondary" [disabled]="taskPage===1||busy()" (click)="changePage(-1)">Previous</button><button class="button secondary" [disabled]="taskPage*50>=page.total||busy()" (click)="changePage(1)">Next</button></div></div><p class="panel-padding muted">Tasks record planned and performed response actions. Update them inside their incident investigation; recording a task does not execute commands on endpoints.</p><div class="table-scroll"><table><thead><tr><th>Incident</th><th>Action</th><th>Target</th><th>Owner</th><th>Status</th><th>Result</th><th>Manage</th></tr></thead><tbody>@for(row of page.items;track row.id){<tr><td>{{row.incidentNumber}}</td><td>{{actionTypes[row.actionType]}}<br>{{row.description}}</td><td>{{row.targetValue||'-'}}</td><td>{{row.owner}}</td><td>{{taskStatuses[row.status]}}</td><td>{{row.result||'-'}}</td><td><a [routerLink]="['/incidents',row.incidentId]">Open investigation</a></td></tr>}@empty{<tr><td colspan="7">No response actions match this filter. Create an action from an incident investigation.</td></tr>}</tbody></table></div></section>}}
 @if(view==='resources'){
 <div class="soc-tiles">@for(resource of resources;track resource.path){<article class="soc-tile"><h3>{{resource.name}}</h3><div class="tile-body"><p>{{resource.description}}</p><a class="button secondary" [routerLink]="resource.path">Open {{resource.name}}</a></div></article>}</div>
 <section class="panel panel-padding"><h2>Data source scope</h2><p>Windows event collection powers event analytics. Incident associations power asset and MITRE coverage. Traffic bandwidth, network conversations, SNMP performance, report scheduling and a separate case-management module are not available in this build.</p></section>
 }
 `,
})
export class SocWorkspace {
 private readonly http=inject(HttpClient);private readonly destroyRef=inject(DestroyRef);private readonly route=inject(ActivatedRoute);
 protected readonly view=this.route.snapshot.data['soc'] as string;
 protected readonly title=({overview:'Incident overview',attacks:'MITRE ATT&CK coverage',analytics:'Event analytics',tasks:'Response tasks',resources:'Resources'} as Record<string,string>)[this.view];
 protected readonly data=signal<Snapshot|null>(null);protected readonly tasks=signal<{total:number;items:Task[]}|null>(null);
 protected readonly busy=signal(false);protected readonly live=signal(true);protected readonly errors=signal<string[]>([]);protected readonly refreshed=signal<Date|null>(null);
 protected readonly selectedTechnique=signal<Technique|null>(null);protected readonly linked=signal<IncidentRow[]>([]);protected readonly event=signal<EventRow|null>(null);
 protected readonly utc=utcTimestamp;protected readonly Math=Math;protected readonly categories=categories;protected readonly statuses=statuses;
 protected readonly colors=['#80aa3f','#efb531','#e5563f','#ae2727'];protected readonly severityNames=['Low','Medium','High','Critical'];
 protected readonly taskStatuses=['Planned','In progress','Completed','Failed','Rolled back'];
 protected readonly actionTypes=['Disable user','Block IP','Block domain','Block hash','Isolate endpoint','Reset password','Remove malware','Reimage device','Revoke sessions','Patch system','Restore backup','Other'];
 protected readonly resources=[{path:'/dashboard',name:'Dashboard',description:'Live telemetry and SQL incident metrics.'},{path:'/attack-matrix',name:'MITRE reference',description:'Loaded technique catalog and investigation references.'},{path:'/iocs',name:'Indicators',description:'Search indicators and review their verdicts.'},{path:'/incidents',name:'Investigations',description:'Evidence, timeline, comments, associations and response actions.'}];
 protected query='';protected hours=24;protected minutes=60;protected activeOnly=false;protected search='';protected channel='';protected taskStatus='';protected taskPage=1;
 protected techniqueSearch='';protected observedOnly=false;protected includeSubs=true;
 private applied:Record<string,string|number|boolean>={};private request?:Subscription;private detailRequest?:Subscription;
 constructor(){this.apply();timer(15000,15000).pipe(takeUntilDestroyed()).subscribe(()=>{if(this.live()&&!document.hidden&&!this.busy())this.load();});this.destroyRef.onDestroy(()=>{this.request?.unsubscribe();this.detailRequest?.unsubscribe();});}
 protected apply(){this.taskPage=1;this.selectedTechnique.set(null);this.linked.set([]);this.event.set(null);this.applied=this.view==='analytics'?{minutes:this.minutes,search:this.search,channel:this.channel,query:this.query}:this.view==='tasks'?{status:this.taskStatus}:{hours:this.hours,activeOnly:this.activeOnly};if(this.applied['status']==='')delete this.applied['status'];this.load();}
 private load(extra:Record<string,string|number>={}){if(this.view==='resources')return;this.request?.unsubscribe();this.busy.set(true);this.errors.set([]);
 const params=new HttpParams({fromObject:{...this.applied,...(this.view==='tasks'?{page:this.taskPage}:{}),...extra}});
 this.request=this.http.get<Snapshot & {items:Task[]}>('/api/soc/'+this.view,{params}).pipe(finalize(()=>this.busy.set(false))).subscribe({next:d=>{if(this.view==='tasks')this.tasks.set({total:d.total,items:d.items});else this.data.set(d);this.refreshed.set(new Date());},error:e=>this.errors.set(apiErrors(e))});}
 protected olderEvents(){const id=this.data()?.items.at(-1)?.id;if(id){this.live.set(false);this.load({before:id});}}
 protected changePage(delta:number){this.taskPage+=delta;this.load();}
 protected inspect(id:number){this.detailRequest?.unsubscribe();this.event.set(null);this.detailRequest=this.http.get<EventRow>('/api/windows-events/'+id).subscribe({next:e=>{this.event.set(e);},error:e=>this.errors.set(apiErrors(e))});}
 protected selectTechnique(t:Technique){this.detailRequest?.unsubscribe();this.selectedTechnique.set(t);this.linked.set([]);this.detailRequest=this.http.get<IncidentRow[]>('/api/soc/techniques/'+t.id+'/incidents',{params:{hours:Number(this.applied['hours'])}}).subscribe({next:rows=>this.linked.set(rows),error:e=>this.errors.set(apiErrors(e))});}
 protected catalogue(d:Snapshot){const q=this.techniqueSearch.toLowerCase();return d.techniques.filter(t=>(this.includeSubs||!t.isSubTechnique)&&(!this.observedOnly||this.count(d,t.id)>0||this.alertCount(d,t.techniqueId)>0)&&(t.name.toLowerCase().includes(q)||t.techniqueId.toLowerCase().includes(q)||t.tactic.toLowerCase().includes(q)));}
 protected alertCount(d:Snapshot,id:string){return d.alertCounts?.find(x=>x.techniqueId===id)?.count??0;}
 protected tactics(d:Snapshot){return [...new Set(d.techniques.map(t=>t.tactic))];}
 protected count(d:Snapshot,id:number){return d.counts.find(x=>x.id===id)?.count??0;}
 protected filteredTechniques(d:Snapshot,tactic:string){return this.catalogue(d).filter(t=>t.tactic===tactic);}
 protected hosts(d:Snapshot){return [...new Map(d.devices.map(x=>[x.id,{id:x.id,name:x.name}])).values()];}
 protected deviceCount(d:Snapshot,id:number,tactic:string){return d.devices.find(x=>x.id===id&&x.tactic===tactic)?.count??0;}
 protected eventMax(d:Snapshot){return Math.max(1,...d.series.map(x=>x.count));}
 protected buckets(d:Snapshot){return Math.ceil(Number(this.applied['minutes'])/d.width);}
 protected incidentBars(d:Snapshot){const totals=new Map<number,number>();for(const row of d.timeline)totals.set(row.bucket,(totals.get(row.bucket)??0)+row.count);const max=Math.max(1,...totals.values());const width=880/(Number(this.applied['hours'])*60/d.bucketMinutes);const stack=new Map<number,number>();return [...d.timeline].sort((a,b)=>a.severity-b.severity).map(row=>{const below=stack.get(row.bucket)??0;stack.set(row.bucket,below+row.count);return {key:row.bucket+':'+row.severity,x:10+row.bucket*width,y:160-(below+row.count)/max*145,width:Math.max(1,width-1),height:row.count/max*145,count:row.count,severity:row.severity};});}
}
