// Presentation only. The tool STATE is computed by the HexStrike gateway policy
// (scan_policy.tool_state) and returned by the API; the UI never derives or overrides it.
// This maps that backend state string to a display label, a badge class, and whether a
// tool in that state may be selected for execution.
export type ToolState =
  | 'available'
  | 'authorized'
  | 'needs_setup'
  | 'blocked'
  | 'unavailable'
  | 'discovered'
  | string;

export interface ToolStateView {
  label: string;
  cls: string;
  selectable: boolean;
}

export function toolStateView(state: ToolState | null | undefined): ToolStateView {
  switch (state) {
    case 'available':
    case 'authorized':
      return { label: 'Available', cls: 'state-available', selectable: true };
    case 'needs_setup':
      return { label: 'Needs setup', cls: 'state-setup', selectable: false };
    case 'blocked':
      return { label: 'Blocked', cls: 'state-blocked', selectable: false };
    case 'unavailable':
      return { label: 'Unavailable', cls: 'state-unavailable', selectable: false };
    case 'discovered':
      return { label: 'Discovered', cls: 'state-discovered', selectable: false };
    default:
      return { label: 'Unknown', cls: 'state-unavailable', selectable: false };
  }
}

// Shared badge styling, included by both the offline catalog and the live builder.
export const TOOL_STATE_STYLES = `
.tool-state{display:inline-block;font-size:11px;font-weight:700;letter-spacing:.04em;text-transform:uppercase;padding:2px 8px;border-radius:999px;border:1px solid transparent;white-space:nowrap}
.tool-state.state-available{background:#e6f5ec;color:#1c7a43;border-color:#aedcc0}
.tool-state.state-setup{background:#fff4e0;color:#8a5a00;border-color:#f0d08a}
.tool-state.state-blocked{background:#fdebec;color:#a3242d;border-color:#f0b4b8}
.tool-state.state-unavailable{background:#eef1f5;color:#59677a;border-color:#d7e0ea}
.tool-state.state-discovered{background:#eef5fb;color:#1d5f8a;border-color:#b8d6ec}
`;
