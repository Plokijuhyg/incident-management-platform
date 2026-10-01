import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ActivatedRoute, Router, convertToParamMap, provideRouter } from '@angular/router';
import { BehaviorSubject } from 'rxjs';
import { IncidentCreate } from './incident-create';
import { IncidentList } from './incident-list';
import { IncidentDetailPage } from './incident-detail';
const incident = {
  id: 42,
  incidentNumber: 'INC-2026-000042',
  title: 'Suspicious login',
  description: '<script>unsafe()</script>',
  severity: 3,
  priority: 2,
  status: 0,
  category: 2,
  source: 5,
  createdByName: 'Analyst',
  createdAt: '2026-09-24T08:00:00Z',
  updatedAt: '2026-09-24T08:00:00Z',
  assignedToName: null,
  version: 0,
};
describe('Incident pages', () => {
  let http: HttpTestingController;
  let params: BehaviorSubject<ReturnType<typeof convertToParamMap>>;
  let query: BehaviorSubject<ReturnType<typeof convertToParamMap>>;
  beforeEach(() => {
    params = new BehaviorSubject(convertToParamMap({ id: '42' }));
    query = new BehaviorSubject(convertToParamMap({}));
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        provideRouter([]),
        {
          provide: ActivatedRoute,
          useValue: {
            paramMap: params,
            queryParamMap: query,
            snapshot: { queryParamMap: convertToParamMap({}) },
          },
        },
      ],
    });
    http = TestBed.inject(HttpTestingController);
  });
  afterEach(() => http.verify());
  function input(fixture: { nativeElement: HTMLElement }, id: string, value: string) {
    const element = fixture.nativeElement.querySelector<HTMLInputElement>(`#${id}`)!;
    element.value = value;
    element.dispatchEvent(new Event('input'));
  }
  it('validates required fields and sends numeric enums and UTC dates exactly once', async () => {
    const fixture = TestBed.createComponent(IncidentCreate);
    await fixture.whenStable();
    const form = fixture.nativeElement.querySelector('form') as HTMLFormElement;
    form.dispatchEvent(new Event('submit', { cancelable: true }));
    await fixture.whenStable();
    http.expectNone('/api/incidents');
    expect(fixture.nativeElement.textContent).toContain('Enter a description');
    input(fixture, 'title', 'Suspicious login');
    input(fixture, 'description', 'Investigate authentication events.');
    input(fixture, 'detectedAt', '2026-09-24T10:30');
    input(fixture, 'occurredAt', '2026-09-24T10:00');
    const navigate = vi.spyOn(TestBed.inject(Router), 'navigate').mockResolvedValue(true);
    form.dispatchEvent(new Event('submit', { cancelable: true }));
    form.dispatchEvent(new Event('submit', { cancelable: true }));
    const request = http.expectOne('/api/incidents');
    expect(request.request.method).toBe('POST');
    expect(request.request.body.severity).toBe(1);
    expect(request.request.body.source).toBe(5);
    expect(request.request.body.detectedAt).toBe(new Date('2026-09-24T10:30').toISOString());
    request.flush(incident);
    await fixture.whenStable();
    expect(navigate).toHaveBeenCalledWith(['/incidents', 42]);
  });
  it('rejects occurrence after detection and displays server validation errors without losing form data', async () => {
    const fixture = TestBed.createComponent(IncidentCreate);
    await fixture.whenStable();
    const form = fixture.nativeElement.querySelector('form') as HTMLFormElement;
    input(fixture, 'title', 'Report');
    input(fixture, 'description', 'Context');
    input(fixture, 'detectedAt', '2026-09-24T10:00');
    input(fixture, 'occurredAt', '2026-09-24T11:00');
    form.dispatchEvent(new Event('submit', { cancelable: true }));
    await fixture.whenStable();
    http.expectNone('/api/incidents');
    expect(fixture.nativeElement.textContent).toContain('must not be later');
    input(fixture, 'occurredAt', '');
    form.dispatchEvent(new Event('submit', { cancelable: true }));
    http
      .expectOne('/api/incidents')
      .flush(
        { errors: { Title: ['A more specific title is required.'] } },
        { status: 400, statusText: 'Bad Request' },
      );
    await fixture.whenStable();
    expect(fixture.nativeElement.textContent).toContain('A more specific title is required.');
    expect(fixture.nativeElement.querySelector('#title').value).toBe('Report');
  });
  it('loads paginated records and cancels obsolete page requests', async () => {
    const fixture = TestBed.createComponent(IncidentList);
    await fixture.whenStable();
    const first = http.expectOne('/api/incidents?page=1&pageSize=25');
    query.next(convertToParamMap({ page: '2' }));
    expect(first.cancelled).toBe(true);
    http.expectOne('/api/incidents?page=2&pageSize=25').flush({
      items: [incident],
      page: 2,
      pageSize: 25,
      totalCount: 26,
      totalPages: 2,
      hasNextPage: false,
      hasPreviousPage: true,
    });
    await fixture.whenStable();
    expect(fixture.nativeElement.textContent).toContain('Suspicious login');
    expect(fixture.nativeElement.textContent).toContain('Critical');
    expect(fixture.nativeElement.textContent).toContain('Page 2 of 2');
    expect(fixture.nativeElement.querySelector('a.incident-link').getAttribute('href')).toBe(
      '/incidents/42',
    );
  });
  it('shows an empty register and a create link', async () => {
    const fixture = TestBed.createComponent(IncidentList);
    await fixture.whenStable();
    http.expectOne('/api/incidents?page=1&pageSize=25').flush({
      items: [],
      page: 1,
      pageSize: 25,
      totalCount: 0,
      totalPages: 0,
      hasNextPage: false,
      hasPreviousPage: false,
    });
    await fixture.whenStable();
    expect(fixture.nativeElement.textContent).toContain('No incidents yet');
    expect(fixture.nativeElement.querySelector('a[href="/incidents/new"]')).toBeTruthy();
  });
  it('renders detail text safely and fetches a new incident on route changes', async () => {
    const fixture = TestBed.createComponent(IncidentDetailPage);
    await fixture.whenStable();
    http.expectOne('/api/incidents/42').flush(incident);
    await fixture.whenStable();
    http.expectOne('/api/incidents/42/evidence').flush([]);
    expect(fixture.nativeElement.textContent).toContain('<script>unsafe()</script>');
    expect(fixture.nativeElement.querySelector('script')).toBeNull();
    expect(fixture.nativeElement.textContent).toContain('Not recorded');
    params.next(convertToParamMap({ id: '43' }));
    http.expectOne('/api/incidents/43').flush({}, { status: 404, statusText: 'Not Found' });
    await fixture.whenStable();
    expect(fixture.nativeElement.textContent).toContain('could not be found');
    expect(fixture.nativeElement.textContent).not.toContain('Suspicious login');
  });
  it('does not request invalid incident identifiers', async () => {
    params.next(convertToParamMap({ id: 'not-an-id' }));
    const fixture = TestBed.createComponent(IncidentDetailPage);
    await fixture.whenStable();
    expect(fixture.nativeElement.textContent).toContain('could not be found');
    http.expectNone((request) => request.url.startsWith('/api/incidents/'));
  });
});
