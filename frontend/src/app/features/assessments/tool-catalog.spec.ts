import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { afterEach, expect, it } from 'vitest';
import { ToolCatalog } from './tool-catalog';

afterEach(() => TestBed.resetTestingModule());

function catalogFixture() {
  return {
    enabled: false,
    categories: ['Network', 'Web'],
    reviewedTotal: 1,
    advertisedTotal: 2,
    total: 3,
    note: 'note',
    tools: [
      { name: 'nmap_scan', category: 'Network', tier: 'safe', status: 'reviewed', description: 'ports', reason: '', runnable: true, state: 'available' },
      { name: 'responder_credential_harvest', category: 'Network', tier: 'unclassified', status: 'advertised', description: 'adv', reason: 'Listens on a segment; cannot be scoped to one IP.', runnable: false, state: 'blocked' },
      { name: 'sqlmap_scan', category: 'Web', tier: 'unclassified', status: 'advertised', description: 'adv', reason: 'Needs an injectable request.', runnable: false, state: 'needs_setup' },
    ],
  };
}

it('renders every tool with its backend state, keeps non-executable ones visible, and flags offline', () => {
  TestBed.configureTestingModule({ providers: [provideHttpClient(), provideHttpClientTesting()] });
  const fixture = TestBed.createComponent(ToolCatalog);
  const http = TestBed.inject(HttpTestingController);
  http.expectOne('/api/assessments/catalog').flush(catalogFixture());
  fixture.detectChanges();

  // Offline: must not claim live availability.
  expect(fixture.nativeElement.textContent).toContain('Live availability cannot be verified');

  const toggles = () => Array.from(fixture.nativeElement.querySelectorAll('.catalog-toggle')) as HTMLButtonElement[];
  toggles().find((b) => b.textContent!.includes('Network'))!.click();
  fixture.detectChanges();
  let text = fixture.nativeElement.textContent as string;
  expect(text).toContain('nmap_scan');
  expect(text).toContain('Available');
  expect(text).toContain('responder_credential_harvest'); // blocked tool not hidden
  expect(text).toContain('Blocked');

  toggles().find((b) => b.textContent!.includes('Web'))!.click();
  fixture.detectChanges();
  text = fixture.nativeElement.textContent as string;
  expect(text).toContain('sqlmap_scan'); // needs_setup tool not hidden
  expect(text).toContain('Needs setup');

  http.verify();
});
