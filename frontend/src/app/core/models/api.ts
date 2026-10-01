export interface User {
  id: number;
  email: string;
  fullName: string;
  roles: string[];
}
export interface LoginResponse {
  accessToken: string;
  expiresIn: number;
  user: User;
}
export interface Page<T> {
  items: T[];
  page: number;
  pageSize: number;
  totalCount: number;
  totalPages: number;
  hasNextPage: boolean;
  hasPreviousPage: boolean;
}
export interface IncidentSummary {
  id: number;
  incidentNumber: string;
  title: string;
  severity: number;
  priority: number;
  status: number;
  category: number;
  assignedToName: string | null;
  createdAt: string;
}
export interface IncidentDetail extends IncidentSummary {
  recommendedActions?: { alertId: number; ruleId: string | null; text: string }[];
  description: string;
  source: number;
  createdById: number;
  createdByName: string;
  assignedToId: number | null;
  occurredAt: string | null;
  detectedAt: string | null;
  updatedAt: string;
  triagedAt: string | null;
  containedAt: string | null;
  resolvedAt: string | null;
  closedAt: string | null;
  resolutionSummary: string | null;
  version: number;
}
export interface CreateIncident {
  title: string;
  description: string;
  severity: number;
  priority: number;
  category: number;
  source: number;
  detectedAt: string | null;
  occurredAt: string | null;
}
export const severities = ['Low', 'Medium', 'High', 'Critical'];
export const priorities = ['Low', 'Medium', 'High', 'Urgent'];
export const statuses = [
  'New',
  'Triaged',
  'Investigating',
  'Contained',
  'Eradicated',
  'Recovering',
  'Resolved',
  'Closed',
  'False positive',
];
export const categories = [
  'Malware',
  'Phishing',
  'Account compromise',
  'Network attack',
  'Data exfiltration',
  'Ransomware',
  'Insider threat',
  'Vulnerability',
  'Unauthorized access',
  'Other',
];
export const sources = [
  'SIEM',
  'EDR',
  'Firewall',
  'IDS',
  'Email security',
  'Manual',
  'User report',
  'Threat intelligence',
  'PenTest',
  'WindowsEvent',
];
export type LoadState<T> = { loading: boolean; data: T | null; errors: string[] };
