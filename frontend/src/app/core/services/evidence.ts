import { HttpClient, HttpErrorResponse } from '@angular/common/http';
import { inject, Injectable } from '@angular/core';
import { catchError, map } from 'rxjs';
import { EvidenceFile } from '../models/operations';
import { utcTimestamp } from './incidents';
export const evidenceExtensions =
  '.png,.jpg,.jpeg,.gif,.txt,.log,.csv,.json,.xml,.pdf,.docx,.xlsx,.pcap,.pcapng,.zip';
export function fileError(file: File): string | null {
  if (!file.size) return 'Choose a file that is not empty.';
  const extension = '.' + file.name.split('.').pop()?.toLowerCase();
  return evidenceExtensions.split(',').includes(extension)
    ? null
    : 'This file extension is not supported.';
}
@Injectable({ providedIn: 'root' })
export class Evidence {
  private readonly http = inject(HttpClient);
  list(id: number) {
    return this.http
      .get<EvidenceFile[]>(`/api/incidents/${id}/evidence`)
      .pipe(map((files) => files.map((f) => ({ ...f, uploadedAt: utcTimestamp(f.uploadedAt) }))));
  }
  upload(id: number, file: File, type: number, description: string) {
    const body = new FormData();
    // Some browsers provide no MIME type for logs/pcap. The server accepts octet-stream.
    body.append(
      'file',
      file.type ? file : new Blob([file], { type: 'application/octet-stream' }),
      file.name,
    );
    body.append('evidenceType', String(type));
    if (description.trim()) body.append('description', description.trim());
    return this.http.post<EvidenceFile>(`/api/incidents/${id}/evidence`, body);
  }
  download(id: number, fileId: number) {
    return this.http
      .get(`/api/incidents/${id}/evidence/${fileId}/download`, { responseType: 'blob' })
      .pipe(
        catchError(async (error: unknown) => {
          if (
            error instanceof HttpErrorResponse &&
            error.error instanceof Blob &&
            error.error.size < 16384
          ) {
            let body: unknown;
            try {
              body = JSON.parse(await error.error.text());
            } catch {
              throw error;
            }
            throw new HttpErrorResponse({
              error: body,
              headers: error.headers,
              status: error.status,
              statusText: error.statusText,
              url: error.url ?? undefined,
            });
          }
          throw error;
        }),
      );
  }
  delete(id: number, fileId: number) {
    return this.http.delete<void>(`/api/incidents/${id}/evidence/${fileId}`);
  }
}
@Injectable({ providedIn: 'root' })
export class Downloads {
  save(blob: Blob, name: string): void {
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = name;
    document.body.append(anchor);
    anchor.click();
    anchor.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
}
