import { HttpBackend, HttpClient } from '@angular/common/http';
import { Injectable, inject, signal } from '@angular/core';
import { Observable, catchError, finalize, map, of, shareReplay, tap } from 'rxjs';
import { LoginResponse, User } from '../models/api';

@Injectable({ providedIn: 'root' })
export class Auth {
  // Auth requests bypass the JWT interceptor, including session restoration.
  private readonly http = new HttpClient(inject(HttpBackend));
  readonly user = signal<User | null>(null);
  private token: string | null = null;
  private expiresAt = 0;
  private initialized = false;
  private restoring?: Observable<boolean>;
  hasRole(role: string): boolean {
    return this.user()?.roles.includes(role) ?? false;
  }
  canManageIncidents(): boolean {
    return this.hasRole('ADMIN') || this.hasRole('SECURITY_MANAGER');
  }
  // Can reach the Assessments module (managers/admin, plus the red-team lab identity).
  canRunAssessments(): boolean {
    return this.canManageIncidents() || this.hasRole('RED_TEAM');
  }
  // A red-team-only user has RED_TEAM and no blue-team role — scoped to Assessments only.
  isRedTeamOnly(): boolean {
    return (
      this.hasRole('RED_TEAM') &&
      !this.hasRole('ADMIN') &&
      !this.hasRole('SECURITY_MANAGER') &&
      !this.hasRole('SOC_ANALYST')
    );
  }
  accessToken(): string | null {
    return this.token;
  }
  isAuthenticated(): boolean {
    return !!this.token && Date.now() < this.expiresAt;
  }
  private accept(response: LoginResponse): void {
    this.token = response.accessToken;
    this.expiresAt = Date.now() + response.expiresIn * 1000;
    this.user.set(response.user);
    this.initialized = true;
  }
  login(email: string, password: string): Observable<LoginResponse> {
    return this.http
      .post<LoginResponse>(
        '/api/auth/login',
        { email: email.trim(), password },
        { withCredentials: true },
      )
      .pipe(tap((result) => this.accept(result)));
  }
  restore(): Observable<boolean> {
    if (this.isAuthenticated()) return of(true);
    if (this.initialized) return of(false);
    return (this.restoring ??= this.http
      .post<LoginResponse>('/api/auth/refresh', {}, { withCredentials: true })
      .pipe(
        tap((result) => this.accept(result)),
        map(() => true),
        catchError(() => {
          this.clear();
          return of(false);
        }),
        finalize(() => {
          this.restoring = undefined;
        }),
        shareReplay({ bufferSize: 1, refCount: false }),
      ));
  }
  logout(): Observable<void> {
    // Keep the session if revocation fails, so the user can retry rather than
    // leaving a valid HttpOnly cookie that silently signs them back in.
    return this.http
      .post<void>('/api/auth/logout', {}, { withCredentials: true })
      .pipe(tap(() => this.clear()));
  }
  clear(): void {
    this.token = null;
    this.expiresAt = 0;
    this.user.set(null);
    this.initialized = true;
  }
}
export function safeReturnUrl(value: string | null): string {
  return value &&
    /^\/(?:incidents|dashboard|users|alerts|iocs|assets|mitre|audit|lab|account|windows-events|assessments|automation|overview|attack-matrix|analytics|tasks|resources)(?:\/|\?|$)/.test(
      value,
    ) &&
    !value.includes('\\')
    ? value
    : '/incidents';
}
