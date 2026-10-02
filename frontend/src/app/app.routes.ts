import { Routes } from '@angular/router';
import { adminGuard, authGuard, guestGuard, managerGuard } from './core/guards/auth';
import { alertsMatcher } from './features/alerts/alerts-matcher';
export const routes: Routes = [
  {
    path: 'login',
    title: 'Sign in | Incident Platform',
    canActivate: [guestGuard],
    loadComponent: () => import('./features/auth/login').then((m) => m.Login),
  },
  {
    path: '',
    canActivate: [authGuard],
    canActivateChild: [authGuard],
    loadComponent: () => import('./layout/shell').then((m) => m.Shell),
    children: [
      { path: '', pathMatch: 'full', redirectTo: 'dashboard' },
      {path: 'overview', data: {soc: 'overview'},  loadComponent: () => import('./features/soc/soc-workspace').then(m => m.SocWorkspace)},
      {path: 'attack-matrix', data: {soc: 'attacks'},  loadComponent: () => import('./features/soc/soc-workspace').then(m => m.SocWorkspace)},
      {path: 'analytics', data: {soc: 'analytics'}, canActivate: [managerGuard], loadComponent: () => import('./features/soc/soc-workspace').then(m => m.SocWorkspace)},
      {path: 'tasks', data: {soc: 'tasks'},  loadComponent: () => import('./features/soc/soc-workspace').then(m => m.SocWorkspace)},
      {path: 'resources', data: {soc: 'resources'},  loadComponent: () => import('./features/soc/soc-workspace').then(m => m.SocWorkspace)},
      { path: 'automation', title: 'Automation & coverage | Incident Platform', canActivate: [managerGuard], loadComponent: () => import('./features/automation/automation').then(m => m.AutomationPage) },
      {
        path: 'assessments',
        title: 'Security Assessments | Incident Platform',
        canActivate: [managerGuard],
        loadComponent: () =>
          import('./features/assessments/assessments').then((m) => m.AssessmentsPage),
      },
      {
        path: 'windows-events',
        title: 'Windows Events | Incident Platform',
        canActivate: [managerGuard],
        loadComponent: () =>
          import('./features/windows-events/windows-events').then((m) => m.WindowsEventsPage),
      },
      {
        path: 'logs',
        title: 'Logs | Incident Platform',
        canActivate: [managerGuard],
        loadComponent: () => import('./features/logs/logs-page').then((m) => m.LogsPage),
      },
      {
        path: 'dashboard',
        title: 'Dashboard | Incident Platform',
        loadComponent: () => import('./features/dashboard/dashboard').then((m) => m.Dashboard),
      },
      {
        path: 'users',
        canActivate: [adminGuard],
        title: 'Users | Incident Platform',
        loadComponent: () => import('./features/users/user-list').then((m) => m.UserList),
      },
      {
        path: 'users/new',
        canActivate: [adminGuard],
        title: 'New user | Incident Platform',
        loadComponent: () => import('./features/users/user-page').then((m) => m.UserPage),
      },
      {
        path: 'users/:id',
        canActivate: [adminGuard],
        title: 'Manage user | Incident Platform',
        loadComponent: () => import('./features/users/user-page').then((m) => m.UserPage),
      },
      {
        matcher: alertsMatcher,
        title: 'Alerts | Incident Platform',
        loadComponent: () => import('./features/alerts/alert-queue').then((m) => m.AlertQueue),
      },
      {
        path: 'iocs',
        data: { kind: 'iocs' },
        title: 'IOCS | Incident Platform',
        loadComponent: () => import('./features/catalog/catalog-page').then((m) => m.CatalogPage),
      },
      {
        path: 'iocs/:id',
        data: { kind: 'iocs' },
        title: 'IOCS | Incident Platform',
        loadComponent: () => import('./features/catalog/catalog-page').then((m) => m.CatalogPage),
      },
      {
        path: 'assets',
        data: { kind: 'assets' },
        title: 'ASSETS | Incident Platform',
        loadComponent: () => import('./features/catalog/catalog-page').then((m) => m.CatalogPage),
      },
      {
        path: 'assets/:id',
        data: { kind: 'assets' },
        title: 'ASSETS | Incident Platform',
        loadComponent: () => import('./features/catalog/catalog-page').then((m) => m.CatalogPage),
      },
      {
        path: 'attack-matrix/:id',
        data: { kind: 'mitre' },
        title: 'MITRE | Incident Platform',
        loadComponent: () => import('./features/catalog/catalog-page').then((m) => m.CatalogPage),
      },
      {
        path: 'audit',
        canActivate: [adminGuard],
        loadComponent: () => import('./features/audit/audit-page').then((m) => m.AuditPage),
      },
      {
        path: 'lab',
        canActivate: [adminGuard],
        loadComponent: () => import('./features/lab/lab-page').then((m) => m.LabPage),
      },
      {
        path: 'account',
        loadComponent: () => import('./features/account/account-page').then((m) => m.AccountPage),
      },
      {
        path: 'forbidden',
        title: 'Access restricted | Incident Platform',
        loadComponent: () => import('./shared/components/forbidden').then((m) => m.Forbidden),
      },
      {
        path: 'incidents',
        title: 'Incidents | Incident Platform',
        loadComponent: () =>
          import('./features/incidents/incident-list').then((m) => m.IncidentList),
      },
      {
        path: 'incidents/new',
        title: 'New incident | Incident Platform',
        loadComponent: () =>
          import('./features/incidents/incident-create').then((m) => m.IncidentCreate),
      },
      {
        path: 'incidents/:id',
        title: 'Incident details | Incident Platform',
        loadComponent: () =>
          import('./features/incidents/incident-detail').then((m) => m.IncidentDetailPage),
      },
      {
        path: '**',
        title: 'Page not found | Incident Platform',
        loadComponent: () => import('./shared/components/not-found').then((m) => m.NotFound),
      },
    ],
  },
];
