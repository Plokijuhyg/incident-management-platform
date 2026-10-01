import { AfterViewInit, Component, ElementRef, input, OnDestroy, output, signal, viewChild } from '@angular/core';
let locks = 0;
let previousOverflow = '';
@Component({
 selector:'app-detail-modal',
 template:`<dialog #dialog [attr.aria-label]="title()" (cancel)="dismiss($event)" (keydown.escape)="dismiss($event)" (click)="backdrop($event)">
 <header><h2>{{title()}}</h2><div class="modal-actions"><button type="button" class="button secondary small" autofocus (click)="closed.emit()" aria-label="Close details">Close <span aria-hidden="true">&times;</span></button>@if(minimizable()){<button type="button" class="button secondary small" (click)="minimized.emit()" aria-label="Minimize details">Minimize</button>}</div></header>
 <div class="modal-content"><ng-content /></div>
 </dialog>`,
 styles:[`:host{display:contents}dialog{position:fixed;inset:0;margin:auto;width:min(1040px,calc(100vw - 32px));max-width:calc(100vw - 32px);max-height:calc(100dvh - 40px);padding:0;border:1px solid #c7d1df;border-radius:12px;background:#fff;color:#233249;box-shadow:0 24px 90px #13243c55;overflow:hidden}dialog[open]{display:flex;flex-direction:column}dialog::backdrop{background:#10223899;backdrop-filter:blur(2px)}header{display:flex;align-items:center;justify-content:space-between;gap:20px;padding:18px 22px;background:#f3f6fa;border-bottom:1px solid #dbe2ec;flex-shrink:0}h2{font-size:18px;margin:0;overflow-wrap:anywhere}header button{flex-shrink:0}.modal-actions{display:flex;gap:8px;flex-wrap:wrap;justify-content:flex-end}.modal-content{overflow:auto;overscroll-behavior:contain;padding:22px;min-height:0;overflow-wrap:anywhere}@media(max-width:600px){dialog{width:calc(100vw - 16px);max-width:calc(100vw - 16px);max-height:calc(100dvh - 16px)}header,.modal-content{padding:14px}}`]
})
export class DetailModal implements AfterViewInit,OnDestroy {
 title=input('Details');minimizable=input(false);minimized=output<void>();closed=output<void>();private dialog=viewChild.required<ElementRef<HTMLDialogElement>>('dialog');
 private opener:HTMLElement|null=null;private locked=false;
 ngAfterViewInit(){this.opener=document.activeElement instanceof HTMLElement?document.activeElement:null;if(locks++===0){previousOverflow=document.body.style.overflow;document.body.style.overflow='hidden';}this.locked=true;this.dialog().nativeElement.showModal();}
 dismiss(event:Event){event.preventDefault();event.stopPropagation();this.closed.emit();}
 backdrop(event:MouseEvent){const d=this.dialog().nativeElement;if(event.target!==d)return;const r=d.getBoundingClientRect();if(event.clientX<r.left||event.clientX>r.right||event.clientY<r.top||event.clientY>r.bottom)this.closed.emit();}
 ngOnDestroy(){this.dialog().nativeElement.close();if(this.locked&&--locks===0)document.body.style.overflow=previousOverflow;if(this.opener?.isConnected)this.opener.focus({preventScroll:true});}
}
@Component({
 selector:'app-info-popup',imports:[DetailModal],
 template:`<button type="button" class="link-button popup-trigger" aria-haspopup="dialog" [attr.aria-expanded]="visible()" (click)="open()"><ng-content select="[popupTrigger]" /></button>
 @if(visible()){<app-detail-modal [title]="title()" (closed)="close()"><ng-content /></app-detail-modal>}`,
 styles:[`:host{display:block;margin:8px 0}.popup-trigger{text-align:left;line-height:1.5;font-weight:600}.popup-trigger:focus-visible{outline:2px solid #286cc1;outline-offset:3px}`]
})
export class InfoPopup {
 title=input('Details');opened=output<void>();closed=output<void>();protected visible=signal(false);
 protected open(){this.visible.set(true);this.opened.emit();}
 protected close(){this.visible.set(false);this.closed.emit();}
}
