import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting, HttpTestingController } from '@angular/common/http/testing';
import { ActivatedRoute, Router, convertToParamMap, provideRouter } from '@angular/router';
import { Login } from './login';
describe('Login page', () => {
  it('validates credentials, reports generic rejection, and preserves a safe return URL', async () => {
    TestBed.configureTestingModule({
      imports: [Login],
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        provideRouter([]),
        {
          provide: ActivatedRoute,
          useValue: {
            snapshot: { queryParamMap: convertToParamMap({ returnUrl: '/incidents/42' }) },
          },
        },
      ],
    });
    const http = TestBed.inject(HttpTestingController);
    const fixture = TestBed.createComponent(Login);
    await fixture.whenStable();
    const form = fixture.nativeElement.querySelector('form') as HTMLFormElement;
    form.dispatchEvent(new Event('submit', { cancelable: true }));
    await fixture.whenStable();
    http.expectNone('/api/auth/login');
    expect(fixture.nativeElement.textContent).toContain('Enter a valid email');
    for (const [id, value] of [
      ['email', 'analyst@example.com'],
      ['password', 'secret'],
    ]) {
      const field = fixture.nativeElement.querySelector(`#${id}`) as HTMLInputElement;
      field.value = value;
      field.dispatchEvent(new Event('input'));
    }
    form.dispatchEvent(new Event('submit', { cancelable: true }));
    http.expectOne('/api/auth/login').flush({}, { status: 401, statusText: 'Unauthorized' });
    await fixture.whenStable();
    expect(fixture.nativeElement.textContent).toContain('Sign-in failed');
    const navigate = vi.spyOn(TestBed.inject(Router), 'navigateByUrl').mockResolvedValue(true);
    form.dispatchEvent(new Event('submit', { cancelable: true }));
    http.expectOne('/api/auth/login').flush({
      accessToken: 'token',
      expiresIn: 900,
      user: { id: 7, fullName: 'Analyst', email: 'analyst@example.com', roles: ['SOC_ANALYST'] },
    });
    await fixture.whenStable();
    expect(navigate).toHaveBeenCalledWith('/incidents/42');
    http.verify();
  });
});
