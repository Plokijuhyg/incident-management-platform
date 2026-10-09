import { inject } from '@angular/core';
import { CanActivateChildFn, CanActivateFn, Router } from '@angular/router';
import { map } from 'rxjs';
import { Auth, safeReturnUrl } from '../services/auth';
export const authGuard: CanActivateFn = (_route, state) => {
  const auth = inject(Auth);
  const router = inject(Router);
  return auth
    .restore()
    .pipe(
      map(
        (ok) => ok || router.createUrlTree(['/login'], { queryParams: { returnUrl: state.url } }),
      ),
    );
};
export const guestGuard: CanActivateFn = (route) => {
  const router = inject(Router);
  return inject(Auth)
    .restore()
    .pipe(
      map((ok) =>
        ok ? router.parseUrl(safeReturnUrl(route.queryParamMap.get('returnUrl'))) : true,
      ),
    );
};

export const adminGuard: CanActivateFn = () => {
  const auth = inject(Auth);
  const router = inject(Router);
  return auth
    .restore()
    .pipe(map((ok) => (ok && auth.hasRole('ADMIN') ? true : router.createUrlTree(['/forbidden']))));
};

export const managerGuard: CanActivateFn = () => {
  const auth = inject(Auth);
  const router = inject(Router);
  return auth
    .restore()
    .pipe(
      map((ok) => (ok && auth.canManageIncidents() ? true : router.createUrlTree(['/forbidden']))),
    );
};

// Assessments module: managers/admin, plus the red-team lab identity.
export const assessmentGuard: CanActivateFn = () => {
  const auth = inject(Auth);
  const router = inject(Router);
  return auth
    .restore()
    .pipe(
      map((ok) => (ok && auth.canRunAssessments() ? true : router.createUrlTree(['/forbidden']))),
    );
};

// Confines a red-team-only user to the Assessments module (and their account page);
// any other in-app route bounces to /assessments. Runs after authGuard, so the
// session is already restored and roles are known. UX only — the API enforces 403.
export const redTeamScopeGuard: CanActivateChildFn = (_route, state) => {
  const auth = inject(Auth);
  const router = inject(Router);
  if (!auth.isRedTeamOnly()) {
    return true;
  }
  const path = state.url.split('?')[0];
  return path.startsWith('/assessments') || path.startsWith('/account')
    ? true
    : router.createUrlTree(['/assessments']);
};
