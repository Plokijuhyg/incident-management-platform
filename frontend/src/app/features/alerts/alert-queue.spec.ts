import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { UrlSegment, convertToParamMap } from '@angular/router';
import { Alerts, incidentSeverityFor } from '../../core/services/alerts';
import { readFilters } from '../incidents/incident-list';
import { readAlertFilters } from './alert-queue';
import { alertsMatcher } from './alerts-matcher';

describe('Alert triage list state', () => {
  it('defaults to the open queue and only accepts values the API understands', () => {
    expect(readAlertFilters(convertToParamMap({}))).toEqual({
      search: '', status: '', source: '', severity: '', open: true, sort: '', dir: '',
    });
    const parsed = readAlertFilters(
      convertToParamMap({ open: 'false', severity: 'High', status: '3', sort: 'severity', dir: 'asc' }),
    );
    expect(parsed).toMatchObject({ open: false, severity: 'High', status: '3', sort: 'severity', dir: 'asc' });
    const hostile = readAlertFilters(
      convertToParamMap({ severity: 'DROP', status: '99', source: '-1', sort: 'rawPayload', dir: 'up', search: 'x'.repeat(500) }),
    );
    expect(hostile).toMatchObject({ severity: '', status: '', source: '', sort: '', dir: '' });
    expect(hostile.search).toHaveLength(200);
  });

  it('matches the queue and a selected alert with one route so the list is reused', () => {
    const segs = (...paths: string[]) => paths.map((p) => new UrlSegment(p, {}));
    expect(alertsMatcher(segs('alerts'))?.posParams).toEqual({});
    expect(alertsMatcher(segs('alerts', '11'))?.posParams?.['id'].path).toBe('11');
    expect(alertsMatcher(segs('alerts', '11', 'extra'))).toBeNull();
    expect(alertsMatcher(segs('incidents'))).toBeNull();
  });

  it('starts promotion from the source severity, tolerating case and unknown values', () => {
    expect(incidentSeverityFor('Critical')).toBe(3);
    expect(incidentSeverityFor(' HIGH ')).toBe(2);
    expect(incidentSeverityFor('informational')).toBe(0);
    expect(incidentSeverityFor('vendor-specific-7')).toBe(1);
  });

  it('sends filters as query parameters and drops empty ones', () => {
    TestBed.configureTestingModule({ providers: [provideHttpClient(), provideHttpClientTesting()] });
    const http = TestBed.inject(HttpTestingController);
    TestBed.inject(Alerts).list(2, 25, { search: 'scan', status: '', openOnly: true, sort: 'severity' }).subscribe();
    const request = http.expectOne((r) => r.url === '/api/alerts');
    expect(request.request.params.keys().sort()).toEqual(['openOnly', 'page', 'pageSize', 'search', 'sort']);
    expect(request.request.params.get('openOnly')).toBe('true');
    request.flush({ items: [], page: 2, pageSize: 25, totalCount: 0, totalPages: 0, hasNextPage: false, hasPreviousPage: false });
    http.verify();
  });
});

describe('Incident register list state', () => {
  it('reads filters from the URL and discards unsupported values', () => {
    expect(readFilters(convertToParamMap({ assignee: 'me', open: 'true', severity: '3', sort: 'severity' }))).toMatchObject({
      assignee: 'me', open: true, severity: '3', sort: 'severity',
    });
    expect(readFilters(convertToParamMap({ assignee: 'root', severity: '4', sort: 'description' }))).toMatchObject({
      assignee: '', severity: '', sort: '',
    });
  });
});
