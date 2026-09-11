import React from 'react';
import type { Alert } from '../types/alert';
import { TIER_CONFIG } from '../types/alert';
import { ShieldAlert, MapPin, AlertCircle, ChevronRight, Hash } from 'lucide-react';

interface AlertFeedProps {
  alerts: Alert[];
  selectedAlert: Alert | null;
  onSelectAlert: (alert: Alert) => void;
}

export const AlertFeed: React.FC<AlertFeedProps> = ({
  alerts,
  selectedAlert,
  onSelectAlert,
}) => {
  // Sort descending by risk_score (0-100 scale)
  const sortedAlerts = [...alerts].sort((a, b) => b.risk_score - a.risk_score);

  return (
    <div className="alert-feed-wrapper">
      <div className="alert-feed-header">
        <div className="feed-title-group">
          <ShieldAlert size={18} className="icon-shield" />
          <span className="feed-title">Flagged Alert Feed</span>
          <span className="feed-count-badge">{alerts.length} Threats</span>
        </div>
        <div className="feed-subtext">Sorted by Risk Score (Desc)</div>
      </div>

      <div className="alert-feed-list">
        {sortedAlerts.length === 0 ? (
          <div className="empty-feed">
            <AlertCircle size={28} />
            <p>No alerts match the selected filter criteria.</p>
          </div>
        ) : (
          sortedAlerts.map((alert) => {
            const tier = TIER_CONFIG[alert.risk_tier];
            const isSelected = selectedAlert?.message_id === alert.message_id;
            const formattedDate = new Date(alert.date).toLocaleString(undefined, {
              month: 'short',
              day: 'numeric',
              hour: '2-digit',
              minute: '2-digit',
            });

            return (
              <div
                key={alert.message_id}
                className={`alert-card ${isSelected ? 'selected' : ''}`}
                onClick={() => onSelectAlert(alert)}
                style={{
                  borderLeftColor: tier.color,
                }}
              >
                <div className="alert-card-top">
                  <div className="alert-tier-badge" style={{ backgroundColor: tier.bg, color: tier.color, borderColor: tier.border }}>
                    <span className="badge-dot" style={{ backgroundColor: tier.color }}></span>
                    {tier.label.toUpperCase()}
                  </div>

                  <div className="alert-score-display">
                    <span className="score-val" style={{ color: tier.color }}>
                      {alert.risk_score.toFixed(1)}
                    </span>
                    <span className="score-scale">/100</span>
                  </div>
                </div>

                <div className="alert-subject" title={alert.subject}>
                  {alert.subject}
                </div>

                <div className="alert-sender" title={alert.from}>
                  From: <strong>{alert.from}</strong>
                </div>

                <div className="alert-card-footer">
                  <div className="footer-meta">
                    {alert.geolocation ? (
                      <span className="geo-tag" title={`${alert.geolocation.city}, ${alert.geolocation.country}`}>
                        <MapPin size={11} /> {alert.geolocation.city}, {alert.geolocation.country}
                      </span>
                    ) : (
                      <span className="geo-tag muted">
                        <MapPin size={11} /> Anonymized Proxy
                      </span>
                    )}
                    <span className="time-tag">{formattedDate}</span>
                  </div>

                  <div className="footer-action">
                    <span className="factors-count" title="Contributing risk factors">
                      <Hash size={11} /> {alert.contributing_factors.length} factors
                    </span>
                    <ChevronRight size={14} className="chevron" />
                  </div>
                </div>

                {/* Visual Risk Gauge Bar (0-100 scale) */}
                <div className="score-bar-bg">
                  <div
                    className="score-bar-fill"
                    style={{
                      width: `${Math.min(Math.max(alert.risk_score, 0), 100)}%`,
                      backgroundColor: tier.color,
                    }}
                  />
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};
