import { Component, input, output } from '@angular/core';
import { Role, roleLabels } from '../../core/models/operations';
@Component({
  selector: 'app-role-picker',
  template: `<div class="role-picker">
    @for (role of roles(); track role.id) {
      <label class="check-label"
        ><input
          type="checkbox"
          [checked]="selected().includes(role.name)"
          [disabled]="disabled() || locked().includes(role.name)"
          (change)="toggle(role.name, $event)"
        /><span
          ><strong>{{ labels[role.name] ?? role.name }}</strong
          ><small>{{ role.description }}</small></span
        ></label
      >
    }
  </div>`,
})
export class RolePicker {
  readonly roles = input.required<Role[]>();
  readonly selected = input.required<string[]>();
  readonly disabled = input(false);
  readonly locked = input<string[]>([]);
  readonly selectionChange = output<string[]>();
  protected readonly labels = roleLabels;
  protected toggle(name: string, event: Event): void {
    if (this.disabled() || this.locked().includes(name)) return;
    const checked = (event.target as HTMLInputElement).checked;
    this.selectionChange.emit(
      checked
        ? [...new Set([...this.selected(), name])]
        : this.selected().filter((role) => role !== name),
    );
  }
}
