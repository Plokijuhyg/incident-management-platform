import { Component } from '@angular/core';
import { LiveActivity } from './dashboard/live-activity';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';
import { Auth } from '../core/services/auth';
import { Downloads } from '../core/services/evidence';
import { IncidentActions } from './incidents/incident-actions';
import { EvidencePanel } from './evidence/evidence-panel';
import { UserEditor } from './users/user-editor';
import { Dashboard } from './dashboard/dashboard';

@Component({selector:'app-live-activity', template:''})
class LiveActivityStub {}

const incident = {
  id: 42,
  title: 'Investigation',
  description: 'Context',
  severity: 2,
  priority: 1,
  category: 2,
  status: 0,
  assignedToId: 7,
  version: 3,
  createdAt: '2026-09-24T08:00:00',
  updatedAt: '2026-09-24T08:00:00',
};
const person = {
  id: 8,
  email: 'analyst@example.com',
  fullName: 'Test analyst',
  jobTitle: null,
  isActive: true,
  roles: ['SOC_ANALYST'],
  createdAt: '2026-09-24T08:00:00',
  lastLoginAt: null,
};
const roles = ['ADMIN', 'SECURITY_MANAGER', 'SOC_ANALYST'].map((name, id) => ({
  id,
  name,
  description: null,
}));
const evidence = {
  id: 5,
  originalFileName: 'audit.log',
  sizeBytes: 20,
  contentType: 'text/plain',
  sha256: 'a'.repeat(64),
  evidenceType: 1,
  description: null,
  uploadedByName: 'Analyst',
  uploadedAt: '2026-09-24T08:00:00',
};
function button(f: ComponentFixture<unknown>, label: string): HTMLButtonElement {
  const found = Array.from(
    f.nativeElement.querySelectorAll('button') as NodeListOf<HTMLButtonElement>,
  ).find((b) => b.textContent?.trim() === label);
  if (!found) throw new Error(`Missing button: ${label}`);
  return found;
}
function input(f: ComponentFixture<unknown>, id: string, value: string) {
  const element = f.nativeElement.querySelector(`#${id}`) as HTMLInputElement;
  element.value = value;
  element.dispatchEvent(new Event('input', { bubbles: true }));
}
function submit(f: ComponentFixture<unknown>, index = 0) {
  f.nativeElement
    .querySelectorAll('form')
    [index].dispatchEvent(new Event('submit', { cancelable: true }));
}
function select(f: ComponentFixture<unknown>, id: string, index: number) {
  const el = f.nativeElement.querySelector(`#${id}`) as HTMLSelectElement;
  el.selectedIndex = index;
  el.dispatchEvent(new Event('change'));
}
describe('Operational workflows', () => {
  let http: HttpTestingController;
  let auth: Auth;
  const save = vi.fn();
  beforeEach(() => {
    save.mockReset();
    TestBed.overrideComponent(Dashboard, {remove:{imports:[LiveActivity]},add:{imports:[LiveActivityStub]}});
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        provideRouter([]),
        { provide: Downloads, useValue: { save } },
      ],
    });
    http = TestBed.inject(HttpTestingController);
    auth = TestBed.inject(Auth);
    auth.user.set({ id: 7, email: 'admin@example.com', fullName: 'Admin', roles: ['ADMIN'] });
  });
  afterEach(() => http.verify());
  async function actions() {
    const f = TestBed.createComponent(IncidentActions);
    f.componentRef.setInput('incident', incident);
    f.componentInstance.updated.subscribe((value) => f.componentRef.setInput('incident', value));
    await f.whenStable();
    return f;
  }
  it('preserves a stale incident draft and requires explicitly loading the latest version', async () => {
    const f = await actions();
    button(f, 'Edit incident').click();
    await f.whenStable();
    input(f, 'edit-title', 'My draft');
    submit(f);
    submit(f);
    const req = http.expectOne('/api/incidents/42');
    expect(req.request.method).toBe('PUT');
    expect(req.request.body.version).toBe(3);
    req.flush({}, { status: 409, statusText: 'Conflict' });
    await f.whenStable();
    expect(f.nativeElement.querySelector('#edit-title').value).toBe('My draft');
    expect(button(f, 'Save changes').disabled).toBe(true);
    button(f, 'Load latest (discard draft)').click();
    http
      .expectOne('/api/incidents/42')
      .flush({ ...incident, title: 'Someone else updated', version: 4 });
    await f.whenStable();
    button(f, 'Edit incident').click();
    await f.whenStable();
    expect(f.nativeElement.querySelector('#edit-title').value).toBe('Someone else updated');
    submit(f);
    const next = http.expectOne('/api/incidents/42');
    expect(next.request.body.version).toBe(4);
    next.flush({ ...incident, version: 5 });
    await f.whenStable();
  });
  it('limits analyst actions to assigned incidents and keeps close in its separate workflow', async () => {
    auth.user.update((u) => ({ ...u!, roles: ['SOC_ANALYST'] }));
    const f = await actions();
    expect(f.nativeElement.textContent).not.toContain('Assign owner');
    expect(f.nativeElement.textContent).not.toContain('Close incident');
    button(f, 'Change status').click();
    await f.whenStable();
    expect(
      Array.from(f.nativeElement.querySelectorAll('option') as NodeListOf<HTMLOptionElement>).map(
        (o) => o.textContent?.trim(),
      ),
    ).not.toContain('Closed');
    select(f, 'incident-status', 2);
    input(f, 'status-note', 'Investigating sign-ins');
    submit(f);
    const req = http.expectOne('/api/incidents/42/status');
    expect(req.request.body).toEqual({ status: 2, note: 'Investigating sign-ins' });
    req.flush({ ...incident, status: 2 });
    await f.whenStable();
    f.componentRef.setInput('incident', { ...incident, assignedToId: 8 });
    await f.whenStable();
    expect(f.nativeElement.querySelectorAll('button').length).toBe(0);
  });
  it('loads active assignees and requires a summary before confirming closure', async () => {
    const f = await actions();
    button(f, 'Assign owner').click();
    await f.whenStable();
    http.expectOne('/api/users/assignable').flush([{ id: 8, fullName: 'Test analyst' }]);
    await f.whenStable();
    select(f, 'assignee', 1);
    submit(f);
    const req = http.expectOne('/api/incidents/42/assign');
    expect(req.request.body).toEqual({ assignedToId: 8 });
    req.flush({ ...incident, assignedToId: 8 });
    await f.whenStable();
    button(f, 'Close incident').click();
    await f.whenStable();
    submit(f);
    http.expectNone('/api/incidents/42/close');
    input(f, 'resolution', '  Access secured.  ');
    submit(f);
    const close = http.expectOne('/api/incidents/42/close');
    expect(close.request.body).toEqual({ resolutionSummary: 'Access secured.' });
    close.flush({ ...incident, status: 7 });
    await f.whenStable();
    expect(f.nativeElement.textContent).toContain('Incident closed.');
  });
  async function files() {
    const f = TestBed.createComponent(EvidencePanel);
    f.componentRef.setInput('incidentId', 42);
    await f.whenStable();
    http.expectOne('/api/incidents/42/evidence').flush([evidence]);
    await f.whenStable();
    return f;
  }
  it('validates files and uploads multipart with browser-managed content type, retaining failed uploads', async () => {
    const f = await files();
    const picker = f.nativeElement.querySelector('#evidence-file') as HTMLInputElement;
    function choose(file: File) {
      Object.defineProperty(picker, 'files', { value: [file], configurable: true });
      picker.dispatchEvent(new Event('change'));
    }
    choose(new File(['x'], 'bad.exe'));
    await f.whenStable();
    expect(button(f, 'Upload evidence').disabled).toBe(true);
    choose(new File([], 'empty.log'));
    await f.whenStable();
    expect(f.nativeElement.textContent).toContain('not empty');
    choose(new File(['events'], 'capture.pcap'));
    await f.whenStable();
    submit(f);
    const req = http.expectOne('/api/incidents/42/evidence');
    expect(req.request.method).toBe('POST');
    expect(req.request.headers.has('Content-Type')).toBe(false);
    const data = req.request.body as FormData;
    expect(data.get('evidenceType')).toBe('7');
    expect((data.get('file') as File).name).toBe('capture.pcap');
    expect((data.get('file') as File).type).toBe('application/octet-stream');
    req.flush({}, { status: 413, statusText: 'Payload Too Large' });
    await f.whenStable();
    expect(f.nativeElement.textContent).toContain('size limit');
    expect(button(f, 'Upload evidence').disabled).toBe(false);
    submit(f);
    http.expectOne('/api/incidents/42/evidence').flush(evidence);
    http.expectOne('/api/incidents/42/evidence').flush([evidence]);
    await f.whenStable();
    expect(button(f, 'Upload evidence').disabled).toBe(true);
  });
  it('downloads binary evidence and requires explicit confirmation before deleting', async () => {
    const f = await files();
    button(f, 'Download').click();
    const req = http.expectOne('/api/incidents/42/evidence/5/download');
    expect(req.request.responseType).toBe('blob');
    const blob = new Blob(['events']);
    req.flush(blob);
    await f.whenStable();
    expect(save).toHaveBeenCalledWith(blob, 'audit.log');
    button(f, 'Delete').click();
    await f.whenStable();
    http.expectNone('/api/incidents/42/evidence/5');
    button(f, 'Confirm delete').click();
    const deletion = http.expectOne('/api/incidents/42/evidence/5');
    expect(deletion.request.method).toBe('DELETE');
    deletion.flush(null);
    await f.whenStable();
    expect(f.nativeElement.textContent).toContain('No evidence uploaded yet.');
  });
  it('hides evidence deletion from analysts', async () => {
    auth.user.update((u) => ({ ...u!, roles: ['SOC_ANALYST'] }));
    const f = await files();
    expect(f.nativeElement.textContent).not.toContain('Delete');
    expect(button(f, 'Download')).toBeTruthy();
  });
  async function editor(user: typeof person | null) {
    const f = TestBed.createComponent(UserEditor);
    f.componentRef.setInput('user', user);
    f.componentRef.setInput('roles', roles);
    f.componentInstance.saved.subscribe((value) => f.componentRef.setInput('user', value));
    await f.whenStable();
    return f;
  }
  it('validates user credentials and roles before creating a user', async () => {
    const f = await editor(null);
    submit(f);
    http.expectNone('/api/users');
    input(f, 'user-name', 'New analyst');
    input(f, 'user-email', 'new@example.com');
    input(f, 'new-password', 'weak');
    submit(f);
    http.expectNone('/api/users');
    input(f, 'new-password', 'SecurePass123');
    submit(f);
    submit(f);
    const req = http.expectOne('/api/users');
    expect(req.request.body).toEqual({
      fullName: 'New analyst',
      email: 'new@example.com',
      password: 'SecurePass123',
      jobTitle: null,
      roles: ['SOC_ANALYST'],
    });
    req.flush(person);
    await f.whenStable();
    expect(f.nativeElement.querySelector('#new-password')).toBeNull();
  });
  it('saves roles without losing a profile draft and confirms deactivation', async () => {
    const f = await editor(person);
    input(f, 'user-name', 'Unsaved name');
    const boxes = f.nativeElement.querySelectorAll(
      'input[type=checkbox]',
    ) as NodeListOf<HTMLInputElement>;
    boxes[1].click();
    submit(f, 1);
    const req = http.expectOne('/api/users/8/roles');
    expect(req.request.body.roles).toEqual(['SOC_ANALYST', 'SECURITY_MANAGER']);
    req.flush({ ...person, roles: ['SOC_ANALYST', 'SECURITY_MANAGER'] });
    await f.whenStable();
    expect(f.nativeElement.querySelector('#user-name').value).toBe('Unsaved name');
    button(f, 'Deactivate user').click();
    await f.whenStable();
    http.expectNone('/api/users/8/deactivate');
    button(f, 'Confirm deactivation').click();
    http.expectOne('/api/users/8/deactivate').flush(null);
    await f.whenStable();
    expect(f.nativeElement.textContent).toContain('Account deactivated.');
  });
  it('prevents self-deactivation and locks the current administrator role', async () => {
    const f = await editor({ ...person, id: 7, roles: ['ADMIN'] });
    expect(f.nativeElement.textContent).toContain('You cannot deactivate your own account.');
    expect(f.nativeElement.querySelector('input[type=checkbox]').disabled).toBe(true);
    expect(f.nativeElement.textContent).not.toContain('Confirm deactivation');
  });
  function flushDashboard(
    days = 30,
    interval = 'day',
    timeline = [{ start: '2026-09-24T00:00:00', count: 2 }],
  ) {
    const requests = http.match((r) => r.url.startsWith('/api/dashboard/'));
    expect(requests.length).toBe(8);
    for (const req of requests) {
      if (req.request.url.endsWith('/metrics')) {
        expect(req.request.params.get('periodDays')).toBe(String(days));
        req.flush({
          meanTimeToDetectMinutes: 0,
          meanTimeToContainMinutes: null,
          meanTimeToResolveMinutes: 120,
          sampleSize: 2,
          periodDays: days,
          detectionSampleSize: 1,
          containmentSampleSize: 0,
          resolutionSampleSize: 1,
        });
      } else if (req.request.url.endsWith('/incidents-over-time')) {
        expect(req.request.params.get('days')).toBe(String(days));
        expect(req.request.params.get('interval')).toBe(interval);
        req.flush(timeline);
      } else if (req.request.url.endsWith('/summary'))
        req.flush({
          totalIncidents: 2,
          openIncidents: 1,
          criticalOpenIncidents: 0,
          unassignedIncidents: 1,
          myOpenIncidents: 0,
          newAlerts: 0,
          incidentsCreatedToday: 2,
        });
      else req.flush([]);
    }
  }
  it('renders real zero versus unavailable metrics and requests the selected reporting period', async () => {
    const f = TestBed.createComponent(Dashboard);
    await f.whenStable();
    flushDashboard();
    await f.whenStable();
    expect(f.nativeElement.textContent).toContain('0 min');
    expect(f.nativeElement.textContent).toContain('No data');
    expect(f.nativeElement.textContent).toContain('120 min');
    expect(f.nativeElement.textContent).toContain('2 incidents in the selected period.');
    expect(f.nativeElement.querySelectorAll('.sample-caution').length).toBe(2);
    expect(f.nativeElement.querySelector('.trend-series').getAttribute('points')).toBe('414,30');
    expect(f.nativeElement.querySelectorAll('.trend-point').length).toBe(1);
    select(f, 'dashboard-period', 0);
    await f.whenStable();
    flushDashboard(7);
    await f.whenStable();
    select(f, 'dashboard-interval', 1);
    await f.whenStable();
    flushDashboard(7, 'week');
    await f.whenStable();
  });
  it('renders an all-zero time series at the baseline without invalid coordinates', async () => {
    const f = TestBed.createComponent(Dashboard);
    await f.whenStable();
    flushDashboard(30, 'day', [
      { start: '2026-09-23T00:00:00', count: 0 },
      { start: '2026-09-24T00:00:00', count: 0 },
    ]);
    await f.whenStable();
    expect(f.nativeElement.querySelector('.trend-series').getAttribute('points')).toBe(
      '48,210 780,210',
    );
    expect(f.nativeElement.querySelectorAll('.trend-point').length).toBe(2);
  });
  it('shows dashboard errors and retries without fabricating totals', async () => {
    const f = TestBed.createComponent(Dashboard);
    await f.whenStable();
    const requests = http.match((r) => r.url.startsWith('/api/dashboard/'));
    requests[0].flush({}, { status: 500, statusText: 'Server Error' });
    await f.whenStable();
    expect(f.nativeElement.querySelectorAll('.stat-card').length).toBe(0);
    button(f, 'Try again').click();
    flushDashboard();
    await f.whenStable();
    expect(f.nativeElement.querySelectorAll('.stat-card').length).toBe(7);
  });
});
