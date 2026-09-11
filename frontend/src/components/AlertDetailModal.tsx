import React, { useState } from 'react';
import type { Alert } from '../types/alert';
import { TIER_CONFIG } from '../types/alert';
import {
  X,
  ShieldAlert,
  MapPin,
  Calendar,
  Mail,
  FileCode,
  CheckCircle2,
  AlertTriangle,
  Info,
  Copy,
  Check,
} from 'lucide-react';

interface AlertDetailModalProps {
  alert: Alert | null;
  onClose: () => void;
}

export const AlertDetailModal: React.FC<AlertDetailModalProps> = ({ alert, onClose }) => {
  const [showJson, setShowJson] = useState(false);
  const [copied, setCopied] = useState(false);

  if (!alert) return null;

  const tier = TIER_CONFIG[alert.risk_tier];
  const formattedDate = new Date(alert.date).toLocaleString(undefined, {
    weekday: 'short',
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    timeZoneName: 'short',
  });

  const handleCopyJson = () => {
    navigator.clipboard.writeText(JSON.stringify(alert, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal-dialog" onClick={(e) => e.stopPropagation()}>
        {/* Header */}
        <div className="modal-header" style={{ borderBottomColor: tier.border }}>
          <div className="modal-header-left">
            <div
              className="modal-tier-badge"
              style={{
                backgroundColor: tier.bg,
                color: tier.color,
                borderColor: tier.border,
              }}
            >
              <ShieldAlert size={14} />
              <span>{tier.label.toUpperCase()} THREAT</span>
            </div>
            <span className="modal-msg-id">{alert.message_id}</span>
          </div>

          <div className="modal-header-actions">
            <button
              className={`json-toggle-btn ${showJson ? 'active' : ''}`}
              onClick={() => setShowJson(!showJson)}
              title="Toggle Task 6 JSON Schema"
            >
              <FileCode size={14} />
              <span>{showJson ? 'Card View' : 'Raw JSON'}</span>
            </button>
            <button className="modal-close-btn" onClick={onClose}>
              <X size={18} />
            </button>
          </div>
        </div>

        {/* Body */}
        <div className="modal-body">
          {showJson ? (
            <div className="raw-json-container">
              <div className="raw-json-toolbar">
                <span className="json-hint">Task 6 Risk Output Schema (0–100 scale)</span>
                <button className="copy-json-btn" onClick={handleCopyJson}>
                  {copied ? <Check size={14} /> : <Copy size={14} />}
                  <span>{copied ? 'Copied' : 'Copy JSON'}</span>
                </button>
              </div>
              <pre className="json-code-block">{JSON.stringify(alert, null, 2)}</pre>
            </div>
          ) : (
            <>
              {/* Risk Score Summary Banner */}
              <div className="risk-banner" style={{ borderColor: tier.border, background: tier.bg }}>
                <div className="risk-banner-score">
                  <span className="big-score" style={{ color: tier.color }}>
                    {alert.risk_score.toFixed(2)}
                  </span>
                  <span className="score-total">/ 100.00</span>
                  <span className="tier-tag-label" style={{ color: tier.color }}>
                    {tier.label} Severity
                  </span>
                </div>
                <div className="risk-banner-gauge">
                  <div className="gauge-track">
                    <div
                      className="gauge-fill"
                      style={{
                        width: `${Math.min(Math.max(alert.risk_score, 0), 100)}%`,
                        backgroundColor: tier.color,
                      }}
                    />
                  </div>
                  <div className="gauge-labels">
                    <span>0 (Clean)</span>
                    <span>29 (Low)</span>
                    <span>59 (Med)</span>
                    <span>84 (High)</span>
                    <span>100 (Critical)</span>
                  </div>
                </div>
              </div>

              {/* Email Metadata Grid */}
              <div className="meta-section">
                <div className="meta-row">
                  <span className="meta-label">
                    <Mail size={14} /> From:
                  </span>
                  <span className="meta-value email-address">{alert.from}</span>
                </div>
                <div className="meta-row">
                  <span className="meta-label">Subject:</span>
                  <span className="meta-value subject-text">{alert.subject}</span>
                </div>
                <div className="meta-row">
                  <span className="meta-label">
                    <Calendar size={14} /> Date:
                  </span>
                  <span className="meta-value">{formattedDate}</span>
                </div>
              </div>

              {/* Geolocation Card */}
              <div className="detail-card">
                <div className="card-title">
                  <MapPin size={15} />
                  <span>Sender Geolocation Forensics</span>
                </div>
                {alert.geolocation ? (
                  <div className="geo-info-grid">
                    <div className="geo-item">
                      <span className="geo-lbl">City</span>
                      <span className="geo-val">{alert.geolocation.city}</span>
                    </div>
                    <div className="geo-item">
                      <span className="geo-lbl">Country Code</span>
                      <span className="geo-val">{alert.geolocation.country}</span>
                    </div>
                    <div className="geo-item">
                      <span className="geo-lbl">Latitude</span>
                      <span className="geo-val">{alert.geolocation.lat.toFixed(4)}°</span>
                    </div>
                    <div className="geo-item">
                      <span className="geo-lbl">Longitude</span>
                      <span className="geo-val">{alert.geolocation.long.toFixed(4)}°</span>
                    </div>
                  </div>
                ) : (
                  <div className="geo-null-notice">
                    <Info size={16} />
                    <span>
                      <strong>Geolocation Unavailable / Anonymized:</strong> Sender routed through an anonymized proxy, Tor exit node, or originating IP headers were suppressed.
                    </span>
                  </div>
                )}
              </div>

              {/* Contributing Factors */}
              <div className="detail-card">
                <div className="card-title">
                  <AlertTriangle size={15} />
                  <span>Contributing Risk Factors ({alert.contributing_factors.length})</span>
                </div>
                {alert.contributing_factors.length === 0 ? (
                  <div className="clean-notice">
                    <CheckCircle2 size={16} />
                    <span>No negative risk factors identified. Routine email communication.</span>
                  </div>
                ) : (
                  <ul className="factors-list">
                    {alert.contributing_factors.map((factor, idx) => {
                      const isCritical =
                        factor.toLowerCase().includes('fail') ||
                        factor.toLowerCase().includes('malicious') ||
                        factor.toLowerCase().includes('phishing probability 9') ||
                        factor.toLowerCase().includes('impossible travel');

                      return (
                        <li key={idx} className={`factor-item ${isCritical ? 'critical-factor' : ''}`}>
                          <span className="factor-bullet" style={{ backgroundColor: tier.color }} />
                          <span className="factor-text">{factor}</span>
                        </li>
                      );
                    })}
                  </ul>
                )}
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
};
