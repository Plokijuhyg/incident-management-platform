import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';
import { DataForm } from '../shared/components/data-form';
import { InvestigationPanel } from './incidents/investigation-panel';
import { LabPage } from './lab/lab-page';

describe('Investigation and lab workspace', () => {
  let http: HttpTestingController;
  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting(), provideRouter([])],
    });
    http = TestBed.inject(HttpTestingController);
  });
  afterEach(() => http.verify());
  it('preserves an unverified verdict and blocks duplicate submissions while busy', async () => {
    const f = TestBed.createComponent(DataForm);
    const saved = vi.fn();
    f.componentRef.setInput('fields', [
      {
        key: 'isMalicious',
        label: 'Verdict',
        type: 'select',
        options: [
          { label: 'Unknown', value: null },
          { label: 'Benign', value: false },
        ],
      },
    ]);
    f.componentRef.setInput('value', { isMalicious: null });
    f.componentInstance.saved.subscribe(saved);
    await f.whenStable();
    const submit = () =>
      f.nativeElement
        .querySelector('form')
        .dispatchEvent(new Event('submit', { cancelable: true }));
    submit();
    expect(saved).toHaveBeenLastCalledWith({ isMalicious: null });
    f.componentRef.setInput('busy', true);
    await f.whenStable();
    submit();
    expect(saved).toHaveBeenCalledTimes(1);
  });
  it('adds an internal comment and escapes its contents', async () => {
    const f = TestBed.createComponent(InvestigationPanel);
    f.componentRef.setInput('incidentId', 42);
    await f.whenStable();
    http.expectOne('/api/incidents/42/comments').flush([]);
    await f.whenStable();
    const input = f.nativeElement.querySelector('textarea');
    input.value = '<img src=x onerror=alert(1)>';
    input.dispatchEvent(new Event('input'));
    f.nativeElement.querySelector('form').dispatchEvent(new Event('submit', { cancelable: true }));
    const req = http.expectOne('/api/incidents/42/comments');
    expect(req.request.method).toBe('POST');
    expect(req.request.body.isInternal).toBe(true);
    req.flush({ id: 1 });
    http
      .expectOne('/api/incidents/42/comments')
      .flush([{ id: 1, body: input.value, authorName: 'Analyst', isInternal: true }]);
    await f.whenStable();
    expect(f.nativeElement.querySelector('.activity-feed img')).toBeNull();
    expect(f.nativeElement.textContent).toContain('<img src=x');
  });
  it('never checks a service automatically and reports unavailable without claiming readiness', async () => {
    const f = TestBed.createComponent(LabPage);
    await f.whenStable();
    http
      .expectOne('/api/lab/connections')
      .flush({ hexStrikeUrl: 'http://127.0.0.1:8888', ollamaUrl: 'http://127.0.0.1:11434' });
    await f.whenStable();
    http.expectNone((r) => r.method === 'POST');
    expect(f.nativeElement.textContent).toContain('Not checked');
    f.nativeElement.querySelector('button').click();
    http
      .expectOne('/api/lab/connections/hexstrike/check')
      .flush({
        service: 'hexstrike',
        url: 'http://127.0.0.1:8888',
        reachable: false,
        message: 'Service unavailable.',
        checkedAt: '2026-09-25T10:00:00Z',
      });
    await f.whenStable();
    expect(f.nativeElement.textContent).toContain('Unavailable');
    expect(f.nativeElement.textContent).toContain('are separate checks');
    const gatewayButton = Array.from(f.nativeElement.querySelectorAll('button') as NodeListOf<HTMLButtonElement>).find(b=>b.textContent?.includes('Check assessment gateway'))!;
    gatewayButton.click();
    http.expectOne('/api/assessments/capabilities').flush({connected:false,message:'MCP manifest unavailable',tools:[]});
    await f.whenStable();
    expect(f.nativeElement.textContent).toContain('Gateway or MCP unavailable');
    expect(f.nativeElement.textContent).not.toContain('Live MCP connected');
  });
});
