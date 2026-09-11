import React from 'react';
import type { Alert } from '../types/alert';
import { ShieldAlert, AlertTriangle, Globe2, Activity } from 'lucide-react';

interface StatsCardsProps {
  alerts: Alert[];
}

export const StatsCards: React.FC<StatsCardsProps> = ({ alerts }) => {
  const total = alerts.length;
  const critical = alerts.filter((a) => a.risk_tier === 'critical').length;
  const high = alerts.filter((a) => a.risk_tier === 'high').length;
  const geocoded = alerts.filter((a) => a.geolocation !== null).length;
  const avgScore = total > 0 ? (alerts.reduce((acc, a) => acc + a.risk_score, 0) / total).toFixed(1) : '0.0';

  return (
    <div className="stats-cards-grid">
      <div className="stat-card">
        <div className="stat-icon-wrapper blue">
          <Activity size={18} />
        </div>
        <div className="stat-content">
          <span className="stat-label">Total Ingested</span>
          <span className="stat-value">{total}</span>
        </div>
      </div>

      <div className="stat-card">
        <div className="stat-icon-wrapper red">
          <ShieldAlert size={18} />
        </div>
        <div className="stat-content">
          <span className="stat-label">Critical Tier</span>
          <span className="stat-value red-text">{critical}</span>
        </div>
      </div>

      <div className="stat-card">
        <div className="stat-icon-wrapper orange">
          <AlertTriangle size={18} />
        </div>
        <div className="stat-content">
          <span className="stat-label">High Tier</span>
          <span className="stat-value orange-text">{high}</span>
        </div>
      </div>

      <div className="stat-card">
        <div className="stat-icon-wrapper green">
          <Globe2 size={18} />
        </div>
        <div className="stat-content">
          <span className="stat-label">Geocoded Origins</span>
          <span className="stat-value">{geocoded}</span>
        </div>
      </div>

      <div className="stat-card">
        <div className="stat-icon-wrapper purple">
          <Activity size={18} />
        </div>
        <div className="stat-content">
          <span className="stat-label">Avg Risk Score</span>
          <span className="stat-value">{avgScore} <span className="stat-unit">/100</span></span>
        </div>
      </div>
    </div>
  );
};
