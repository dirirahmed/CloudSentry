import type { FormEvent } from "react";

export const REGION_PATTERN = /^[a-z]{2}(-[a-z]+)+-\d{1,2}$/;

const COMMON_REGIONS = [
  "ca-central-1", "ca-west-1", "us-east-1", "us-east-2", "us-west-1", "us-west-2",
  "eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1", "eu-north-1",
  "ap-south-1", "ap-southeast-1", "ap-southeast-2", "ap-northeast-1", "ap-northeast-2", "sa-east-1",
];

interface Props {
  region: string;
  includeAi: boolean;
  scanning: boolean;
  onRegionChange: (region: string) => void;
  onIncludeAiChange: (includeAi: boolean) => void;
  onScan: () => void;
}

export default function ScanControls({ region, includeAi, scanning, onRegionChange, onIncludeAiChange, onScan }: Props) {
  const trimmed = region.trim();
  const regionInvalid = trimmed !== "" && !REGION_PATTERN.test(trimmed);

  function handleSubmit(event: FormEvent) {
    event.preventDefault();
    if (!regionInvalid && !scanning) onScan();
  }

  return (
    <form className="scan-controls" onSubmit={handleSubmit} aria-label="Scan settings">
      <div className="field">
        <label htmlFor="region">AWS region</label>
        <input
          id="region"
          list="region-options"
          value={region}
          placeholder="Server default"
          autoComplete="off"
          spellCheck={false}
          aria-invalid={regionInvalid}
          aria-describedby="region-help"
          disabled={scanning}
          onChange={(event) => onRegionChange(event.target.value)}
        />
        <datalist id="region-options">
          {COMMON_REGIONS.map((code) => (
            <option key={code} value={code} />
          ))}
        </datalist>
        <p id="region-help" className={regionInvalid ? "field-help field-error" : "field-help"}>
          {regionInvalid ? "Use a region code such as ca-central-1." : "Leave empty to use the backend's AWS_REGION."}
        </p>
      </div>

      <div className="field">
        <label className="toggle">
          <input
            type="checkbox"
            role="switch"
            checked={includeAi}
            disabled={scanning}
            onChange={(event) => onIncludeAiChange(event.target.checked)}
          />
          <span className="toggle-track" aria-hidden="true" />
          Include AI analysis
        </label>
        <p className="field-help">Amazon Bedrock explains findings. It never changes severity.</p>
      </div>

      <button type="submit" className="scan-button" disabled={scanning || regionInvalid}>
        {scanning ? "Scanning…" : "Run security scan"}
      </button>
    </form>
  );
}
