import { HttpErrorResponse } from '@angular/common/http';
export function apiErrors(error: unknown): string[] {
  if (!(error instanceof HttpErrorResponse)) return ['Something went wrong. Please try again.'];
  if (error.status === 0) return ['Cannot reach the server. Check your connection and try again.'];
  if (error.status === 401) return ['Your session has ended. Please sign in again.'];
  if (error.status === 403) return ['You do not have permission to perform this action.'];
  if (error.status === 404)
    return ['The requested record could not be found or is no longer available.'];
  if (error.status === 429) {
    const delay = Number(error.headers.get('Retry-After'));
    return [
      Number.isFinite(delay) && delay > 0
        ? `Too many requests. Try again in ${Math.ceil(delay)} seconds.`
        : 'Too many requests. Please wait before trying again.',
    ];
  }
  if (error.status === 413)
    return ['This file exceeds the server upload limit. Choose a smaller file.'];
  if (error.status === 415) return ['This file type is not supported.'];
  if (typeof error.error === 'string' && error.status === 400) return [error.error];
  if (error.status >= 500) return ['The server could not complete the request. Please try again.'];
  const body: unknown = error.error;
  if (body && typeof body === 'object') {
    const problem = body as { errors?: Record<string, unknown>; title?: unknown };
    if (problem.errors && typeof problem.errors === 'object') {
      const messages = Object.values(problem.errors).flatMap((value) =>
        Array.isArray(value) ? value.filter((x): x is string => typeof x === 'string') : [],
      );
      if (messages.length) return messages;
    }
    if (typeof problem.title === 'string') return [problem.title];
  }
  return ['The request could not be completed. Please try again.'];
}
