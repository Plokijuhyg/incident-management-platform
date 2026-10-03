import { Component, DestroyRef, computed, inject, signal } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { InfoPopup } from '../../shared/components/detail-modal';

interface ToolEntry {
  name: string;
  category: string;
  tier: string;
  status: string; // 'reviewed' | 'advertised'
  description: string;
  reason: string;
  runnable: boolean;
}
interface Catalog {
  enabled: boolean;
  categories: string[];
  reviewedTotal: number;
  advertisedTotal: number;
  total: number;
  note: string;
  tools: ToolEntry[];
}

/**
 * The offline catalog of supported assessment tools. Visible before the Kali gateway
 * is connected, so an analyst can see what the platform can run and what it would take
 * to enable the rest. Reviewed tools can execute once connected; advertised tools are
 * shown for planning only. No tool runs from this view.
 */
@Component({
  selector: 'app-tool-catalog',
  imports: [InfoPopup],
  template: `
    <section class="panel panel-padding section-space">
      <div class="catalog-heading">
        <div>
          <h2>Supported tools</h2>
          <p class="muted small-text">
            The assessment tools the platform supports, by category. Reviewed tools run once the
            Kali gateway is connected and installed; advertised tools are shown for planning only.
          </p>
        </div>
        @if (catalog(); as c) {
          <div class="catalog-counts">
            <span class="badge severity-0">{{ c.reviewedTotal }} reviewed</span>
            <span class="badge neutral">{{ c.advertisedTotal }} advertised</span>
          </div>
        }
      </div>
      @if (catalog(); as c) {
        @if (!c.enabled) {
          <p class="notice">
            The Kali gateway is not connected (Laptop 2 not configured). This catalog is
            informational; install the tools on Kali and connect the gateway to run the reviewed
            checks.
          </p>
        }
        <p class="muted small-text">Choose a category to view its tools.</p>
        @for (category of c.categories; track category) {
          <div class="catalog-category">
            <button
              type="button"
              class="catalog-toggle"
              (click)="toggle(category)"
              [attr.aria-expanded]="isExpanded(category)"
            >
              <span class="catalog-arrow" aria-hidden="true">{{
                isExpanded(category) ? '▾' : '▸'
              }}</span>
              {{ category }}
              <span class="muted small-text">({{ byCategory(category).length }} tools)</span>
            </button>
            @if (isExpanded(category)) {
              <div class="tool-cards">
                @for (tool of byCategory(category); track tool.name) {
                  <div class="tool-card" [class.advertised]="!tool.runnable">
                    <div class="tool-card-top">
                      <code>{{ tool.name }}</code>
                      @if (tool.runnable) {
                        <span
                          class="badge"
                          [class.severity-0]="tool.tier === 'safe'"
                          [class.severity-2]="tool.tier !== 'safe'"
                        >
                          {{ tool.tier === 'safe' ? 'Standard' : 'Confirm' }}
                        </span>
                      } @else {
                        <span class="badge neutral">Needs setup</span>
                      }
                    </div>
                    <p class="tool-desc">{{ tool.description }}</p>
                    @if (!tool.runnable && tool.reason) {
                      <app-info-popup title="{{ tool.name }} — why it cannot run yet">
                        <span popupTrigger class="link-button">Why unavailable</span>
                        <p>{{ tool.reason }}</p>
                      </app-info-popup>
                    }
                  </div>
                }
              </div>
            }
          </div>
        }
        <p class="muted small-text">{{ c.note }}</p>
      } @else if (failed()) {
        <p class="muted">Tool catalog unavailable.</p>
      } @else {
        <p class="muted" role="status">Loading tool catalog...</p>
      }
    </section>
  `,
  styles: [
    `
      .catalog-heading {
        display: flex;
        justify-content: space-between;
        gap: 16px;
        flex-wrap: wrap;
        align-items: flex-start;
      }
      .catalog-counts {
        display: flex;
        gap: 8px;
        flex: none;
      }
      .catalog-category {
        margin-top: 10px;
        border-top: 1px solid var(--border);
      }
      .catalog-toggle {
        all: unset;
        display: flex;
        align-items: center;
        gap: 8px;
        width: 100%;
        box-sizing: border-box;
        cursor: pointer;
        padding: 12px 4px;
        font-weight: 700;
      }
      .catalog-toggle:focus-visible {
        outline: 3px solid #1d949c;
        outline-offset: 2px;
      }
      .catalog-arrow {
        color: var(--teal);
        width: 14px;
      }
      .tool-cards {
        margin-bottom: 14px;
        display: grid;
        grid-template-columns: repeat(auto-fill, minmax(260px, 1fr));
        gap: 12px;
      }
      .tool-card {
        border: 1px solid var(--border);
        border-radius: 8px;
        padding: 12px 14px;
        background: #fff;
      }
      .tool-card.advertised {
        background: #f7f9fc;
        border-style: dashed;
      }
      .tool-card-top {
        display: flex;
        justify-content: space-between;
        align-items: center;
        gap: 8px;
        margin-bottom: 6px;
      }
      .tool-card code {
        font-size: 13px;
        overflow-wrap: anywhere;
      }
      .tool-desc {
        font-size: 13px;
        margin: 0 0 6px;
        color: #30353b;
      }
    `,
  ],
})
export class ToolCatalog {
  private readonly http = inject(HttpClient);
  protected readonly catalog = signal<Catalog | null>(null);
  protected readonly failed = signal(false);
  protected readonly expanded = signal<ReadonlySet<string>>(new Set());
  private readonly tools = computed(() => this.catalog()?.tools ?? []);

  constructor() {
    this.http
      .get<Catalog>('/api/assessments/catalog')
      .pipe(takeUntilDestroyed(inject(DestroyRef)))
      .subscribe({ next: (c) => this.catalog.set(c), error: () => this.failed.set(true) });
  }
  protected byCategory(category: string): ToolEntry[] {
    return this.tools().filter((t) => t.category === category);
  }
  protected isExpanded(category: string): boolean {
    return this.expanded().has(category);
  }
  protected toggle(category: string): void {
    const next = new Set(this.expanded());
    next.has(category) ? next.delete(category) : next.add(category);
    this.expanded.set(next);
  }
}
