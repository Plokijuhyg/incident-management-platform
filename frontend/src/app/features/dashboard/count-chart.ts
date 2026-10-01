import { Component, computed, input, signal } from '@angular/core';
import { CountBucket } from '../../core/models/operations';
@Component({
 selector:'app-count-chart',
 template:`<section class="panel panel-padding chart-panel"><h2>{{title()}}</h2>
 @if(!rows().length){<p class="muted chart-empty">No records yet. Counts appear when matching records are stored.</p>}
 @else{
 <div class="chart-layout"><div class="ring" [style.background]="gradient()" role="img" [attr.aria-label]="title()+': '+total()+' records'"><div><strong>{{selected()?.count ?? total()}}</strong><span>{{selected()?.label || 'Total'}}</span></div></div>
 <ul class="series">@for(row of rows();track row.label;let i=$index){<li><button type="button" [class.selected]="selected()?.label===row.label" (click)="selected.set(selected()?.label===row.label?null:row)" [attr.aria-pressed]="selected()?.label===row.label"><span class="dot" [style.background]="color(row.label,i)"></span><span>{{label(row.label)}}</span><strong>{{row.count}}</strong><small>{{total()?Math.round(row.count/total()*100):0}}%</small></button><div class="track"><span [style.background]="color(row.label,i)" [style.width.%]="row.count/maximum()*100"></span></div></li>}</ul></div>
 @if(total()===0){<p class="muted">No incidents in this dataset yet. Event collection alone does not create incidents; review detection and promotion policies.</p>}
 }</section>`,
 styles:[`.chart-layout{display:flex;gap:24px;align-items:center;margin-top:20px}.ring{width:150px;height:150px;flex:none;border-radius:50%;display:grid;place-items:center}.ring>div{width:112px;height:112px;border-radius:50%;background:white;display:flex;flex-direction:column;align-items:center;justify-content:center;text-align:center;padding:8px}.ring strong{font-size:26px}.ring span{font-size:12px}.series{flex:1;list-style:none;padding:0;margin:0;min-width:0}.series li{margin:9px 0}.series button{width:100%;display:flex;gap:8px;align-items:center;text-align:left;background:none;border:1px solid transparent;padding:4px;border-radius:4px;color:inherit;cursor:pointer;font:inherit}.series button:hover,.series button.selected{background:#edf4fb;border-color:#83b5e0}.series strong{margin-left:auto}.series small{width:34px;text-align:right}.dot{width:10px;height:10px;border-radius:50%;flex:none}.track{height:5px;background:#edf0f4;margin:3px 4px 0;border-radius:3px}.track span{height:100%;display:block;border-radius:3px;transition:width .25s}@media(max-width:650px){.chart-layout{flex-direction:column;align-items:stretch}.ring{align-self:center}}`],
})
export class CountChart {
 readonly title=input.required<string>();readonly rows=input.required<CountBucket[]>();protected readonly selected=signal<CountBucket|null>(null);protected readonly Math=Math;
 protected readonly total=computed(()=>this.rows().reduce((sum,row)=>sum+row.count,0));protected readonly maximum=computed(()=>Math.max(1,...this.rows().map(r=>r.count)));
 protected color(label:string,index:number){return ({Critical:'#c92a3d',High:'#ed6a3c',Medium:'#e5ac29',Low:'#279a79',New:'#3386ce',Closed:'#64748b',Resolved:'#279a79',Investigating:'#8b5fc7',Contained:'#1b9ba6'} as Record<string,string>)[label]||['#3386ce','#8b5fc7','#1b9ba6','#e5ac29','#ed6a3c','#279a79'][index%6];}
 protected readonly gradient=computed(()=>{if(!this.total())return '#e4eaf0';let p=0;return 'conic-gradient('+this.rows().map((r,i)=>({r,i})).filter(({r})=>r.count>0).map(({r,i})=>{const start=p;p+=r.count/this.total()*100;return this.color(r.label,i)+' '+start+'% '+p+'%';}).join(',')+')';});
 protected label(value:string){return value.replace(/([a-z])([A-Z])/g,'$1 $2');}
}
