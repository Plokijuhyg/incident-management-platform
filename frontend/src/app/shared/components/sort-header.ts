import { Component, computed, input, output } from '@angular/core';

export type SortDirection = 'asc' | 'desc';
export interface SortState {
  sort: string;
  direction: SortDirection;
}

/** Sortable column header: `<th sortKey="severity" [state]="sort()" (sorted)="...">Severity</th>`. */
@Component({
  selector: 'th[sortKey]',
  host: { scope: 'col', '[attr.aria-sort]': 'ariaSort()' },
  template: `<button type="button" class="sort-button" (click)="toggle()">
    <ng-content /><span class="sort-arrow" aria-hidden="true">{{ arrow() }}</span>
  </button>`,
})
export class SortHeader {
  readonly sortKey = input.required<string>();
  readonly state = input.required<SortState>();
  /** Direction used the first time this column is chosen; dates and severities read newest/worst first. */
  readonly firstDirection = input<SortDirection>('desc');
  readonly sorted = output<SortState>();
  private readonly active = computed(() => this.state().sort === this.sortKey());
  protected readonly ariaSort = computed(() =>
    this.active() ? (this.state().direction === 'asc' ? 'ascending' : 'descending') : null,
  );
  protected readonly arrow = computed(() =>
    this.active() ? (this.state().direction === 'asc' ? '▲' : '▼') : '↕',
  );
  protected toggle(): void {
    const direction = this.active()
      ? this.state().direction === 'asc'
        ? 'desc'
        : 'asc'
      : this.firstDirection();
    this.sorted.emit({ sort: this.sortKey(), direction });
  }
}
