import { TestBed } from '@angular/core/testing';
import {
  ActivatedRouteSnapshot,
  RouterStateSnapshot,
  UrlTree,
  provideRouter,
} from '@angular/router';
import { Observable, firstValueFrom, of } from 'rxjs';
import { Auth } from '../services/auth';
import { authGuard, adminGuard } from './auth';
describe('authGuard', () => {
  for (const signedIn of [true, false])
    it(
      signedIn ? 'allows a restored session' : 'preserves the intended incident route for login',
      async () => {
        TestBed.configureTestingModule({
          providers: [
            provideRouter([]),
            { provide: Auth, useValue: { restore: () => of(signedIn) } },
          ],
        });
        const result = await firstValueFrom(
          TestBed.runInInjectionContext(() =>
            authGuard(
              {} as ActivatedRouteSnapshot,
              { url: '/incidents/42' } as RouterStateSnapshot,
            ),
          ) as Observable<boolean | UrlTree>,
        );
        if (signedIn) expect(result).toBe(true);
        else {
          expect(result).toBeInstanceOf(UrlTree);
          expect((result as UrlTree).queryParams['returnUrl']).toBe('/incidents/42');
        }
      },
    );
});

describe('adminGuard', () => {
  for (const role of ['ADMIN', 'SECURITY_MANAGER', 'SOC_ANALYST']) {
    it(`checks administrator access for ${role}`, async () => {
      TestBed.configureTestingModule({
        providers: [
          provideRouter([]),
          {
            provide: Auth,
            useValue: {
              restore: () => of(true),
              hasRole: (name: string) => name === role,
            },
          },
        ],
      });
      const result = await firstValueFrom(
        TestBed.runInInjectionContext(() =>
          adminGuard({} as ActivatedRouteSnapshot, {} as RouterStateSnapshot),
        ) as Observable<boolean | UrlTree>,
      );
      if (role === 'ADMIN') expect(result).toBe(true);
      else expect((result as UrlTree).toString()).toBe('/forbidden');
    });
  }
});
