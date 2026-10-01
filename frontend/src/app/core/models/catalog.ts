import { Field, choices } from '../../shared/components/data-form';
export type RecordRow = { id: number; [key: string]: unknown };
export const alertSources = [
  'SIEM',
  'EDR',
  'Firewall',
  'IDS',
  'Email security',
  'Manual',
  'PenTest',
  'WindowsEvent',
];
export const alertStatuses = ['New', 'In review', 'False positive', 'Promoted', 'Closed'];
export const iocTypes = [
  'IP address',
  'Domain',
  'URL',
  'MD5',
  'SHA-1',
  'SHA-256',
  'Email',
  'File name',
  'Registry key',
  'User agent',
];
export const confidence = ['Low', 'Medium', 'High', 'Confirmed'];
export const assetTypes = [
  'Workstation',
  'Server',
  'Network device',
  'Cloud resource',
  'Mobile device',
  'Application',
  'User account',
  'Other',
];
export const impactTypes = ['Compromised', 'Suspected', 'Targeted', 'Affected', 'Patient zero'];
export const iocRoles = [
  'Source',
  'Payload',
  'C2',
  'Dropper',
  'Exfiltration target',
  'Affected',
  'Other',
];
export const selectField = (key: string, label: string, values: string[], initial = 0): Field => ({
  key,
  label,
  type: 'select',
  options: choices(values),
  initial,
});
export const textField = (key: string, label: string, required = false, max = 200): Field => ({
  key,
  label,
  required,
  max,
});
export const description: Field = {
  key: 'description',
  label: 'Description',
  type: 'textarea',
  max: 500,
};
export interface Catalog {
  title: string;
  eyebrow: string;
  intro: string;
  endpoint: string;
  columns: { key: string; label: string; values?: string[] }[];
  fields: Field[];
  editFields: Field[];
}
const verdict: Field = {
  key: 'isMalicious',
  label: 'Verdict',
  type: 'select',
  initial: null,
  options: [
    { label: 'Unverified', value: null },
    { label: 'Malicious', value: true },
    { label: 'Benign', value: false },
  ],
};
const iocEdit = [selectField('confidence', 'Confidence', confidence), verdict, description];
const assetEdit = [
  textField('name', 'Name', true),
  selectField('criticality', 'Business criticality', ['Low', 'Medium', 'High', 'Critical']),
  textField('owner', 'Owner'),
  textField('department', 'Department'),
];
export const catalogs: Record<string, Catalog> = {
  alerts: {
    title: 'Alerts',
    eyebrow: 'DETECTION & TRIAGE',
    intro: 'Turn incoming signals into investigated incidents.',
    endpoint: '/api/alerts',
    columns: [
      { key: 'title', label: 'Signal' },
      { key: 'severity', label: 'Severity' },
      { key: 'source', label: 'Source', values: alertSources },
      { key: 'status', label: 'Status', values: alertStatuses },
      { key: 'detectedAt', label: 'Detected' },
    ],
    fields: [
      textField('title', 'Title', true),
      description,
      selectField('source', 'Source', alertSources, 5),
      { key: 'severity', label: 'Source severity', required: true, max: 20, initial: 'Medium' },
      { key: 'detectedAt', label: 'Detected at', type: 'datetime-local', required: true },
      {
        key: 'rawPayload',
        label: 'Original payload (JSON)',
        type: 'textarea',
        hint: 'Optional original tool output in valid JSON.',
      },
    ],
    editFields: [],
  },
  iocs: {
    title: 'Indicators',
    eyebrow: 'THREAT INTELLIGENCE',
    intro: 'Investigate indicators and connect recurring evidence across incidents.',
    endpoint: '/api/iocs',
    columns: [
      { key: 'value', label: 'Indicator' },
      { key: 'type', label: 'Type', values: iocTypes },
      { key: 'confidence', label: 'Confidence', values: confidence },
      { key: 'isMalicious', label: 'Verdict' },
      { key: 'sightingCount', label: 'Sightings' },
    ],
    fields: [
      selectField('type', 'Type', iocTypes),
      textField('value', 'Indicator value', true, 512),
      ...iocEdit,
      textField('source', 'Source', false, 100),
    ],
    editFields: iocEdit,
  },
  assets: {
    title: 'Assets',
    eyebrow: 'ASSET INVENTORY',
    intro: 'Know what you protect, who owns it, and where it has been affected.',
    endpoint: '/api/assets',
    columns: [
      { key: 'collectionStatus', label: 'Log collection' }, { key: 'logEventCount', label: 'Stored events' }, { key: 'lastEventAt', label: 'Last received event' },
      { key: 'name', label: 'Asset' },
      { key: 'ipAddress', label: 'IP address' },
      { key: 'type', label: 'Type', values: assetTypes },
      { key: 'criticality', label: 'Criticality', values: ['Low', 'Medium', 'High', 'Critical'] },
      { key: 'isActive', label: 'Status' },
    ],
    fields: [
      ...assetEdit,
      textField('hostname', 'Hostname'),
      textField('ipAddress', 'IP address'),
      selectField('type', 'Asset type', assetTypes, 1),
      textField('operatingSystem', 'Operating system'),
      textField('macAddress', 'MAC address'),
      textField('location', 'Location'),
    ],
    editFields: [
      ...assetEdit,
      {
        key: 'isActive',
        label: 'Status',
        type: 'select',
        options: [
          { label: 'Active', value: true },
          { label: 'Inactive', value: false },
        ],
      },
    ],
  },
  mitre: {
    title: 'MITRE ATT&CK',
    eyebrow: 'ADVERSARY BEHAVIOR',
    intro: 'Explore techniques and map observed behavior to your investigations.',
    endpoint: '/api/mitre/techniques',
    columns: [
      { key: 'techniqueId', label: 'Technique' },
      { key: 'name', label: 'Name' },
      { key: 'tactic', label: 'Tactic' },
      { key: 'isSubTechnique', label: 'Sub-technique' },
    ],
    fields: [],
    editFields: [],
  },
};
