import { AssessmentAnalysisTasks } from '../features/assessments/assessment-analysis-tasks';
import { Icon } from '../shared/components/icon';
import { FormsModule } from '@angular/forms';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { Component, DestroyRef, inject, signal } from '@angular/core';
import { Router, RouterLink, RouterLinkActive, RouterOutlet } from '@angular/router';
import { finalize } from 'rxjs';
import { Auth } from '../core/services/auth';
import { apiErrors } from '../core/services/api-errors';
import { ErrorNotice } from '../shared/components/error-notice';
@Component({
  imports: [Icon, FormsModule, RouterOutlet, RouterLink, RouterLinkActive, ErrorNotice],
  template: ` <a class="skip-link" href="#main-content">Skip to content</a>
    <div class="app-shell">
      <header class="siem-header">
        <a class="brand" routerLink="/dashboard"><span class="brand-mark">IP</span><span>Incident<span class="brand-accent">SIEM</span></span></a>
        <nav class="primary-tabs" aria-label="Main sections">
          <a routerLink="/dashboard" routerLinkActive="active">Dashboard</a>
          <a routerLink="/alerts" routerLinkActive="active">Alerts</a>
          <a routerLink="/incidents" routerLinkActive="active">Incidents</a>
          @if(auth.canManageIncidents()){<a routerLink="/analytics" routerLinkActive="active">Analytics</a>}
          <a routerLink="/assets" routerLinkActive="active">Assets</a>
          <a routerLink="/resources" routerLinkActive="active">Resources</a>
          <a routerLink="/tasks" routerLinkActive="active">Tasks</a>
          @if(auth.hasRole('ADMIN')){<a routerLink="/users" routerLinkActive="active">Users</a>}
        </nav>
      </header>
      <div class="workspace">
        <header class="topbar">
          <button class="workspace-search" (click)="searchOpen.set(!searchOpen())">
            <app-icon name="search" /><span>Find a workspace page</span>
          </button>
          <div class="account">
            <a class="account-link" routerLink="/account"
              ><span class="avatar">{{ auth.user()?.fullName?.slice(0, 1) }}</span
              >{{ auth.user()?.fullName }}</a
            ><button class="button secondary small" [disabled]="signingOut()" (click)="logout()">
              {{ signingOut() ? 'Signing out...' : 'Sign out' }}
            </button>
          </div>
        </header>
        @if (searchOpen()) {
          <div class="quick-navigation" (keydown.escape)="searchOpen.set(false)">
            <label for="page-search">Go to a page</label
            ><input
              id="page-search"
              [(ngModel)]="search"
              placeholder="Alerts, assets, indicators..."
            />
            @for (link of links; track link.path) {
              @if (
                (!link.admin || auth.hasRole('ADMIN')) &&
                (!link.manager || auth.canManageIncidents()) &&
                link.label.toLowerCase().includes(search.toLowerCase())
              ) {
                <a [routerLink]="link.path" (click)="searchOpen.set(false)"
                  ><app-icon [name]="link.icon" />{{ link.label }} &rarr;</a
                >
              }
            }
            <button class="button secondary small" (click)="searchOpen.set(false)">
              Close navigation
            </button>
          </div>
        }
        <nav class="workspace-tabs" aria-label="Workspace views">
          @for(link of links;track link.path){
            @if((!link.admin || auth.hasRole('ADMIN')) && (!link.manager || auth.canManageIncidents())){
              <a [routerLink]="link.path" routerLinkActive="active"><app-icon [name]="link.icon" />{{link.label}}</a>
            }
          }
        </nav>
        <main id="main-content" tabindex="-1">
          <app-error-notice [messages]="errors()" /><router-outlet />
        </main>
      </div>
    </div>
    @if(analysis.task();as task){
      <aside class="analysis-dock" aria-label="Background assessment analysis">
        <div role="status"><strong>{{task.busy ? 'Ollama is analyzing...' : task.report?.status==='Completed' ? 'Analysis ready' : 'Analysis needs attention'}}</strong><br><span>{{task.label}}</span></div>
        <button class="button secondary small" (click)="restoreAnalysis(task.id)">Restore analysis</button>
        @if(!task.busy){<button class="button secondary small" (click)="analysis.dismiss()" aria-label="Dismiss analysis notification">Dismiss</button>}
      </aside>
    }`,
  styles:[`.analysis-dock{position:fixed;right:20px;bottom:20px;z-index:100;display:flex;align-items:center;gap:14px;flex-wrap:wrap;max-width:calc(100vw - 40px);padding:16px;border:1px solid #94b7de;border-radius:12px;background:#edf5ff;color:#183451;box-shadow:0 8px 30px #10223833}.analysis-dock span{overflow-wrap:anywhere}.analysis-dock strong{font-size:14px}`],
})
export class Shell {
  protected analysis=inject(AssessmentAnalysisTasks);
  protected restoreAnalysis(id:string){
    if(this.router.url.split('?')[0]==='/assessments')this.analysis.restore.next(id);
    else void this.router.navigate(['/assessments'],{queryParams:{assessment:id}});
  }
  protected readonly searchOpen = signal(false);
  protected search = '';
  protected readonly links: {
    path: string;
    label: string;
    icon: string;
    admin: boolean;
    manager?: boolean;
  }[] = [
    { path: '/overview', label: 'Overview', icon: 'dashboard', admin: false },
    { path: '/attack-matrix', label: 'MITRE ATT&CK', icon: 'mitre', admin: false },
    { path: '/dashboard', label: 'Dashboard', icon: 'dashboard', admin: false },
    { path: '/alerts', label: 'Alerts', icon: 'alerts', admin: false },
    { path: '/incidents', label: 'Incidents', icon: 'incidents', admin: false },
    {
      path: '/windows-events',
      label: 'Windows Events',
      icon: 'audit',
      admin: false,
      manager: true,
    },
    { path: '/logs', label: 'Logs', icon: 'audit', admin: false, manager: true },
    { path: '/ueba', label: 'UEBA', icon: 'users', admin: false, manager: true },
    { path: '/automation', label: 'Automation & coverage', icon: 'audit', admin: false, manager: true },
    { path: '/assessments', label: 'Assessments', icon: 'lab', admin: false, manager: true },
    { path: '/iocs', label: 'Indicators', icon: 'iocs', admin: false },
    { path: '/assets', label: 'Assets', icon: 'assets', admin: false },
    { path: '/users', label: 'Users', icon: 'users', admin: true },
    { path: '/audit', label: 'Audit trail', icon: 'audit', admin: true },
    { path: '/lab', label: 'Lab connections', icon: 'lab', admin: true },
    { path: '/account', label: 'My account', icon: 'account', admin: false },
  ];
  private readonly destroyRef = inject(DestroyRef);
  protected readonly auth = inject(Auth);
  private readonly router = inject(Router);
  protected readonly signingOut = signal(false);
  protected readonly errors = signal<string[]>([]);
  protected logout(): void {
    if (this.signingOut()) return;
    this.signingOut.set(true);
    this.errors.set([]);
    this.auth
      .logout()
      .pipe(
        takeUntilDestroyed(this.destroyRef),
        finalize(() => this.signingOut.set(false)),
      )
      .subscribe({
        next: () => void this.router.navigateByUrl('/login'),
        error: (e) => this.errors.set(apiErrors(e)),
      });
  }
}
