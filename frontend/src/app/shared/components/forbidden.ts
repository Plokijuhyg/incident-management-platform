import { Component } from '@angular/core';
import { RouterLink } from '@angular/router';
@Component({
  imports: [RouterLink],
  template: `<section class="empty-state">
    <p class="eyebrow">ACCESS RESTRICTED</p>
    <h1>Administrator access required</h1>
    <p>Your account cannot manage users. Contact your administrator if you need access.</p>
    <a class="button" routerLink="/incidents">Back to incidents</a>
  </section>`,
})
export class Forbidden {}
