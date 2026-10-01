import { HttpErrorResponse, HttpInterceptorFn } from '@angular/common/http';
import { inject } from '@angular/core';
import { Router } from '@angular/router';
import { catchError, throwError } from 'rxjs';
import { Auth } from '../services/auth';

export const authInterceptor: HttpInterceptorFn = (request, next) => {
  const auth = inject(Auth);
  const router = inject(Router);
  const url = new URL(request.url, window.location.origin);
  // Never send credentials to external origins or non-API paths.
  if (url.origin !== window.location.origin || !url.pathname.startsWith('/api/'))
    return next(request);
  const token = auth.accessToken();
  const authenticated = token
    ? request.clone({ setHeaders: { Authorization: `Bearer ${token}` } })
    : request;
  return next(authenticated).pipe(
    catchError((error: unknown) => {
      if (
        error instanceof HttpErrorResponse &&
        error.status === 401 &&
        token === auth.accessToken()
      ) {
        auth.clear();
        void router.navigate(['/login'], { queryParams: { returnUrl: router.url, expired: '1' } });
      }
      return throwError(() => error);
    }),
  );
};
