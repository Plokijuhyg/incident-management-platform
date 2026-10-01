import { inject } from '@angular/core';
import { CanActivateFn, Router } from '@angular/router';
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
