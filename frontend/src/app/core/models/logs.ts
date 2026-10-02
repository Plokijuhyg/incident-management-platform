// Mirrors the backend LogEvent DTOs. Enums arrive as numbers (the API's wire format).
export const logSourceTypes = ['Generic', 'Syslog', 'Firewall', 'VPN', 'API'];
export const logFormats = ['Syslog', 'Firewall', 'VPN', 'JSON', 'Key=value'];
// Syslog severity 0..7; lower is worse.
export const logSeverities = [
  'Emergency',
  'Alert',
  'Critical',
  'Error',
  'Warning',
  'Notice',
  'Info',
  'Debug',
];

export interface LogSummary {
  id: number;
  source: string;
  sourceType: number;
  host: string | null;
  eventTime: string;
  receivedAt: string;
  severity: number;
  action: string | null;
  outcome: string | null;
  sourceIp: string | null;
  destinationIp: string | null;
  user: string | null;
  message: string;
  enriched: boolean;
  alertId: number | null;
}

export interface LogDetail extends LogSummary {
  facility: string | null;
  sourcePort: number | null;
  destinationPort: number | null;
  protocol: string | null;
  rawLog: string;
  fieldsJson: string | null;
  enrichmentJson: string | null;
}

export interface LogSourceStat {
  sourceType: string;
  source: string;
  count: number;
  lastEventAt: string | null;
}
export interface LogSummaryStats {
  totalStored: number;
  lastReceivedAt: string | null;
  eventsLastHour: number;
  alertsRaised: number;
  sources: LogSourceStat[];
}
