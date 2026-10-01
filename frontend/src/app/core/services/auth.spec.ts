import { TestBed } from '@angular/core/testing';
import { HttpClient, provideHttpClient, withInterceptors } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { provideRouter, Router } from '@angular/router';
import { firstValueFrom } from 'rxjs';
import { Auth, safeReturnUrl } from './auth';
import { authInterceptor } from '../interceptors/auth';
const session = {
  accessToken: 'test-access-token',
  expiresIn: 900,
  user: { id: 7, email: 'analyst@example.com', fullName: 'Analyst', roles: ['SOC_ANALYST'] },
};
describe('Authentication and JWT interceptor', () => {
  let auth: Auth;
  let http: HttpTestingController;
  let client: HttpClient;
  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(withInterceptors([authInterceptor])),
        provideHttpClientTesting(),
        provideRouter([]),
      ],
    });
    auth = TestBed.inject(Auth);
    http = TestBed.inject(HttpTestingController);
    client = TestBed.inject(HttpClient);
  });
  afterEach(() => http.verify());
  async function login() {
    const result = firstValueFrom(auth.login(' analyst@example.com ', 'password'));
    const request = http.expectOne('/api/auth/login');
    expect(request.request.withCredentials).toBe(true);
    expect(request.request.headers.has('Authorization')).toBe(false);
    expect(request.request.body.email).toBe('analyst@example.com');
    request.flush(session);
    await result;
  }
  it('signs in without putting tokens into browser storage', async () => {
    const local = vi.spyOn(Storage.prototype, 'setItem');
    await login();
    expect(auth.user()?.id).toBe(7);
    expect(auth.isAuthenticated()).toBe(true);
    expect(local).not.toHaveBeenCalled();
    local.mockRestore();
  });
  it('shares one refresh request between simultaneous route guards', async () => {
    const first = firstValueFrom(auth.restore());
    const second = firstValueFrom(auth.restore());
    const request = http.expectOne('/api/auth/refresh');
    expect(request.request.withCredentials).toBe(true);
    request.flush(session);
    expect(await first).toBe(true);
    expect(await second).toBe(true);
    expect(await firstValueFrom(auth.restore())).toBe(true);
  });
  it('treats a missing refresh cookie as signed out and does not loop', async () => {
    const result = firstValueFrom(auth.restore());
    http.expectOne('/api/auth/refresh').flush({}, { status: 401, statusText: 'Unauthorized' });
    expect(await result).toBe(false);
    expect(await firstValueFrom(auth.restore())).toBe(false);
    http.expectNone('/api/auth/refresh');
  });
  it('sends JWT only to same-origin API requests', async () => {
    await login();
    for (const url of [
      '/api/incidents',
      'https://external.example/api/incidents',
      '/assets/config.json',
    ]) {
      const result = firstValueFrom(client.get(url));
      const request = http.expectOne(url);
      expect(request.request.headers.get('Authorization')).toBe(
        url === '/api/incidents' ? 'Bearer test-access-token' : null,
      );
      request.flush({});
      await result;
    }
  });
  it('clears the session and redirects on an API 401', async () => {
    await login();
    const navigate = vi.spyOn(TestBed.inject(Router), 'navigate').mockResolvedValue(true);
    const result = firstValueFrom(client.get('/api/incidents')).catch((e) => e);
    http.expectOne('/api/incidents').flush({}, { status: 401, statusText: 'Unauthorized' });
    await result;
    expect(auth.user()).toBeNull();
    expect(navigate).toHaveBeenCalledWith(
      ['/login'],
      expect.objectContaining({ queryParams: expect.objectContaining({ expired: '1' }) }),
    );
  });
  it('does not clear a newer session for an older request that fails late', async () => {
    await login();
    const old = firstValueFrom(client.get('/api/incidents')).catch((e) => e);
    const request = http.expectOne('/api/incidents');
    const newer = firstValueFrom(auth.login('analyst@example.com', 'password'));
    http.expectOne('/api/auth/login').flush({ ...session, accessToken: 'new-token' });
    await newer;
    request.flush({}, { status: 401, statusText: 'Unauthorized' });
    await old;
    expect(auth.accessToken()).toBe('new-token');
  });
  it('keeps the session on a failed logout and clears it after revocation succeeds', async () => {
    await login();
    const failed = firstValueFrom(auth.logout()).catch((e) => e);
    http.expectOne('/api/auth/logout').flush({}, { status: 503, statusText: 'Unavailable' });
    await failed;
    expect(auth.isAuthenticated()).toBe(true);
    const success = firstValueFrom(auth.logout());
    http.expectOne('/api/auth/logout').flush(null);
    await success;
    expect(auth.accessToken()).toBeNull();
    expect(auth.user()).toBeNull();
  });
  it('restricts login return URLs to incident routes', () => {
    expect(safeReturnUrl('/incidents/12')).toBe('/incidents/12');
    expect(safeReturnUrl('/incidents?page=2')).toBe('/incidents?page=2');
    for (const value of ['https://external.example', '//external.example', '/login', null])
      expect(safeReturnUrl(value)).toBe('/incidents');
  });
});
