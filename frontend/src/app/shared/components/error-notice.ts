import { Component, input } from '@angular/core';
@Component({
  selector: 'app-error-notice',
  template: `@if (messages().length) {
    <div class="error-notice" role="alert">
      <strong>Unable to complete your request</strong>
      <ul>
        @for (message of messages(); track $index) {
          <li>{{ message }}</li>
        }
      </ul>
    </div>
  }`,
})
export class ErrorNotice {
  readonly messages = input<string[]>([]);
}
