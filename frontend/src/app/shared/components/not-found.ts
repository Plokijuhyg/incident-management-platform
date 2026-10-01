import { Component } from '@angular/core';
import { RouterLink } from '@angular/router';
@Component({
  imports: [RouterLink],
  template:
    '<section class="empty-state"><p class="eyebrow">404</p><h1>Page not found</h1><p>The page you requested does not exist.</p><a class="button" routerLink="/incidents">Back to incidents</a></section>',
})
export class NotFound {}
