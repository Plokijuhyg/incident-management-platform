import { Component, inject, input, output, OnChanges } from '@angular/core';
import { FormBuilder, ReactiveFormsModule, Validators } from '@angular/forms';
export interface Field {
  key: string;
  label: string;
  type?: 'text' | 'textarea' | 'select' | 'datetime-local' | 'password' | 'number';
  required?: boolean;
  max?: number;
  options?: { label: string; value: string | number | boolean | null }[];
  initial?: unknown;
  hint?: string;
}
export const choices = (values: string[]) => values.map((label, value) => ({ label, value }));
@Component({
  selector: 'app-data-form',
  imports: [ReactiveFormsModule],
  template: ` <form [formGroup]="form" (ngSubmit)="submit()" novalidate>
    <fieldset [disabled]="busy()">
      <div class="form-grid">
        @for (field of fields(); track field.key) {
          <div [class.full-width]="field.type === 'textarea'">
            <label [for]="prefix() + field.key"
              >{{ field.label }}{{ field.required ? ' *' : '' }}</label
            >
            @switch (field.type) {
              @case ('select') {
                <select [id]="prefix() + field.key" [formControlName]="field.key">
                  @for (option of field.options; track $index) {
                    <option [ngValue]="option.value">{{ option.label }}</option>
                  }
                </select>
              }
              @case ('textarea') {
                <textarea
                  [id]="prefix() + field.key"
                  [formControlName]="field.key"
                  rows="4"
                  [attr.maxlength]="field.max ?? null"
                ></textarea>
              }
              @default {
                <input
                  [id]="prefix() + field.key"
                  [type]="field.type ?? 'text'"
                  [formControlName]="field.key"
                  [attr.maxlength]="field.max ?? null"
                  [attr.autocomplete]="field.type === 'password' ? 'new-password' : null"
                />
              }
            }
            @if (field.hint) {
              <small>{{ field.hint }}</small>
            }
            @if (form.get(field.key)?.touched && form.get(field.key)?.invalid) {
              <p class="field-error">Check {{ field.label.toLowerCase() }}.</p>
            }
          </div>
        }
      </div>
    </fieldset>
    <div class="form-actions">
      <button class="button" [disabled]="busy()">{{ busy() ? 'Saving...' : label() }}</button>
    </div>
  </form>`,
})
export class DataForm implements OnChanges {
  readonly fields = input.required<Field[]>();
  readonly value = input<Record<string, unknown>>({});
  readonly busy = input(false);
  readonly label = input('Save');
  readonly prefix = input('field-');
  readonly saved = output<Record<string, unknown>>();
  protected readonly form = inject(FormBuilder).group({});
  ngOnChanges(changes: Record<string, unknown>) {
    if (!changes['fields'] && !changes['value']) return;
    for (const key of Object.keys(this.form.controls)) this.form.removeControl(key);
    for (const f of this.fields()) {
      const rules = [];
      if (f.required) {
        rules.push(Validators.required);
        if (f.type !== 'select' && f.type !== 'number') rules.push(Validators.pattern(/\S/));
      }
      if (f.max) rules.push(Validators.maxLength(f.max));
      this.form.addControl(
        f.key,
        injectControl(
          Object.prototype.hasOwnProperty.call(this.value(), f.key)
            ? this.value()[f.key]
            : f.initial === undefined
              ? ''
              : f.initial,
          rules,
        ),
      );
    }
  }
  protected submit() {
    this.form.markAllAsTouched();
    if (this.form.invalid || this.busy()) return;
    this.saved.emit(this.form.getRawValue());
  }
}
import { FormControl, ValidatorFn } from '@angular/forms';
function injectControl(value: unknown, rules: ValidatorFn[]) {
  return new FormControl(value, rules);
}
