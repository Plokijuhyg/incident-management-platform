import { User } from './api';
export interface ManagedUser extends User {
  jobTitle: string | null;
  isActive: boolean;
  lastLoginAt: string | null;
  createdAt: string;
}
export interface Role {
  id: number;
  name: string;
  description: string | null;
}
export interface Assignee {
  id: number;
  fullName: string;
}
export interface CreateUser {
  email: string;
  fullName: string;
  password: string;
  jobTitle: string | null;
  roles: string[];
}
export interface UpdateIncident {
  title: string;
  description: string;
  severity: number;
  priority: number;
  category: number;
  version: number;
}
export interface EvidenceFile {
  id: number;
  originalFileName: string;
  contentType: string;
  sizeBytes: number;
  sha256: string;
  evidenceType: number;
  description: string | null;
  uploadedByName: string;
  uploadedAt: string;
}
export const evidenceTypes = [
  'Screenshot',
  'Log file',
  'Report',
  'Memory dump',
  'Packet capture',
  'Malware sample',
  'Document',
  'Other',
];
export const roleLabels: Partial<Record<string, string>> = {
  ADMIN: 'Administrator',
  SECURITY_MANAGER: 'Security manager',
  SOC_ANALYST: 'SOC analyst',
};
export interface DashboardSummary {
  totalIncidents: number;
  openIncidents: number;
  criticalOpenIncidents: number;
  unassignedIncidents: number;
  newAlerts: number;
  incidentsCreatedToday: number;
  myOpenIncidents: number;
}
export interface CountBucket {
  label: string;
  count: number;
}
export interface TimeBucket {
  start: string;
  count: number;
}
export interface TechniqueCount {
  techniqueId: string;
  name: string;
  count: number;
}
export interface DashboardMetrics {
  meanTimeToDetectMinutes: number | null;
  meanTimeToContainMinutes: number | null;
  meanTimeToResolveMinutes: number | null;
  sampleSize: number;
  periodDays: number;
  detectionSampleSize: number;
  containmentSampleSize: number;
  resolutionSampleSize: number;
}
