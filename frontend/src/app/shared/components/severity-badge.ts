import { Component, input } from '@angular/core';
import { severities } from '../../core/models/api';
@Component({
  selector: 'app-severity',
  template: `<span class="badge" [class]="'badge severity-' + value()">{{
    labels.at(value()) ?? 'Unknown'
  }}</span>`,
})
export class SeverityBadge {
  readonly value = input.required<number>();
  protected readonly labels = severities;
}
