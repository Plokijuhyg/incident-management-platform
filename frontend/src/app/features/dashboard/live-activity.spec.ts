import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { vi } from 'vitest';
import { Auth } from '../../core/services/auth';
import { LiveActivity } from './live-activity';

describe('Live dashboard activity', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    TestBed.configureTestingModule({ providers: [provideHttpClient(), provideHttpClientTesting(), provideRouter([]),
      { provide: Auth, useValue: { canManageIncidents: () => true } }] });
  });
  afterEach(() => { TestBed.resetTestingModule(); vi.useRealTimers(); });
  it('refreshes actual counts, keeps the last result on failure and stops after destruction', async () => {
    const fixture = TestBed.createComponent(LiveActivity);
    const http = TestBed.inject(HttpTestingController);
    await vi.advanceTimersByTimeAsync(0);
    http.expectOne(r => r.url === '/api/incidents').flush({ items: [] });
    const activity = { observedAt: new Date().toISOString(), enabled: true, windowsSupported: true,
      lastCycleAt: new Date().toISOString(), lastReceivedAt: null, retentionDays: 7,
      storedEvents: 1234, eventsLastMinute: 12, enabledChannels: 1, readableChannels: 1,
      blockedChannels: 0, backlogChannels: 0, latest: [], topChannels: [],
      timeline: Array.from({length:30}, (_, i) => ({start: new Date(Date.now()-i*60000).toISOString(), count: 0})) };
    http.expectOne('/api/windows-events/activity').flush(activity);
    fixture.detectChanges();
    expect(fixture.nativeElement.textContent).toContain('1,234');
    await vi.advanceTimersByTimeAsync(5000);
    http.expectOne('/api/windows-events/activity').flush({ ...activity, storedEvents: 1235 });
    fixture.detectChanges();
    expect(fixture.nativeElement.textContent).toContain('1,235');
    await vi.advanceTimersByTimeAsync(5000);
    http.expectOne('/api/windows-events/activity').flush({}, {status:503, statusText:'Unavailable'});
    fixture.detectChanges();
    expect(fixture.nativeElement.textContent).toContain('1,235');
    expect(fixture.nativeElement.textContent).toContain('may be stale');
    fixture.destroy();
    await vi.advanceTimersByTimeAsync(15000);
    http.verify();
  });
  it('does not request privileged telemetry for analysts', async () => {
    TestBed.overrideProvider(Auth, {useValue:{canManageIncidents: () => false}});
    const fixture=TestBed.createComponent(LiveActivity);
    const http=TestBed.inject(HttpTestingController);
    await vi.advanceTimersByTimeAsync(0);
    http.expectOne(r => r.url === '/api/incidents').flush({items:[]});
    http.expectNone('/api/windows-events/activity');
    fixture.destroy();
    http.verify();
  });
});
