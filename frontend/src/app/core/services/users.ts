import { HttpClient } from '@angular/common/http';
import { inject, Injectable } from '@angular/core';
import { map } from 'rxjs';
import { Page } from '../models/api';
import { Assignee, CreateUser, ManagedUser, Role } from '../models/operations';
import { utcTimestamp } from './incidents';
function normalize(user: ManagedUser): ManagedUser {
  return {
    ...user,
    createdAt: utcTimestamp(user.createdAt),
    lastLoginAt: user.lastLoginAt ? utcTimestamp(user.lastLoginAt) : null,
  };
}
@Injectable({ providedIn: 'root' })
export class Users {
  private readonly http = inject(HttpClient);
  list(page = 1) {
    return this.http
      .get<Page<ManagedUser>>('/api/users', { params: { page, pageSize: 25 } })
      .pipe(map((p) => ({ ...p, items: p.items.map(normalize) })));
  }
  detail(id: number) {
    return this.http.get<ManagedUser>(`/api/users/${id}`).pipe(map(normalize));
  }
  roles() {
    return this.http.get<Role[]>('/api/roles');
  }
  assignable() {
    return this.http.get<Assignee[]>('/api/users/assignable');
  }
  create(request: CreateUser) {
    return this.http.post<ManagedUser>('/api/users', request).pipe(map(normalize));
  }
  update(id: number, request: { fullName: string; jobTitle: string | null }) {
    return this.http.put<ManagedUser>(`/api/users/${id}`, request).pipe(map(normalize));
  }
  replaceRoles(id: number, roles: string[]) {
    return this.http.post<ManagedUser>(`/api/users/${id}/roles`, { roles }).pipe(map(normalize));
  }
  resetPassword(id:number,password:string){return this.http.post<void>(`/api/users/${id}/reset-password`,{password});}
  deactivate(id: number) {
    return this.http.post<void>(`/api/users/${id}/deactivate`, {});
  }
}
