import { Component, input } from '@angular/core';
@Component({
  selector: 'app-icon',
  template: `<svg
    width="20"
    height="20"
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    stroke-width="1.7"
    stroke-linecap="round"
    stroke-linejoin="round"
    aria-hidden="true"
  >
    <path [attr.d]="paths[name()] || paths['dashboard']" />
  </svg>`,
})
export class Icon {
  readonly name = input('dashboard');
  protected paths: Record<string, string> = {
    dashboard: 'M3 3h7v7H3z M14 3h7v7h-7z M3 14h7v7H3z M14 14h7v7h-7z',
    incidents: 'M4 5h16v16H4z M8 3v4 M16 3v4 M8 12h8 M8 16h5',
    alerts: 'M12 3L2 21h20L12 3z M12 9v5 M12 17h.01',
    iocs: 'M10 3a7 7 0 1 0 0 14 7 7 0 0 0 0-14 M15 15l6 6 M7 10h6 M10 7v6',
    assets: 'M3 4h18v12H3z M8 21h8 M12 16v5',
    mitre: 'M12 3v5 M4 16v5 M20 16v5 M4 16h16 M12 8v8 M8 3h8v5H8z',
    users:
      'M9 3a4 4 0 1 0 0 8 4 4 0 0 0 0-8 M2 21v-3a6 6 0 0 1 12 0v3 M17 4a4 4 0 0 1 0 8 M18 15a5 5 0 0 1 4 5',
    audit: 'M5 3h14v18H5z M8 8h8 M8 12h8 M8 16h5',
    lab: 'M9 3h6 M10 3v7L4 20h16l-6-10V3 M7 15h10',
    account: 'M12 3a4 4 0 1 0 0 8 4 4 0 0 0 0-8 M4 21v-2a8 8 0 0 1 16 0v2',
    search: 'M10 3a7 7 0 1 0 0 14 7 7 0 0 0 0-14 M15 15l6 6',
  };
}
