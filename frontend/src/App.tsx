import { useEffect, useState, useMemo } from 'react';
import type { Alert, RiskTier } from './types/alert';
import { ThreatMap } from './components/ThreatMap';
import { AlertFeed } from './components/AlertFeed';
import { FilterBar } from './components/FilterBar';
import { AlertDetailModal } from './components/AlertDetailModal';
import { StatsCards } from './components/StatsCards';
import {
  Shield,
  RefreshCw,
  Wifi,
  WifiOff,
  AlertCircle,
  Cpu,
} from 'lucide-react';
import './App.css';

const API_BASE_URL = 'http://localhost:8000';

export default function App() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedTier, setSelectedTier] = useState<RiskTier | 'all'>('all');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null);
  const [isRefreshing, setIsRefreshing] = useState<boolean>(false);
  const [apiConnected, setApiConnected] = useState<boolean>(false);

  // Fetch alerts from FastAPI backend on load
  const fetchAlerts = async (showLoadingSpinner = true) => {
    if (showLoadingSpinner) setLoading(true);
    setIsRefreshing(true);
    setError(null);

    try {
      const res = await fetch(`${API_BASE_URL}/api/alerts`);
      if (!res.ok) {
        throw new Error(`FastAPI responded with HTTP ${res.status}: ${res.statusText}`);
      }
      const data: Alert[] = await res.json();
      setAlerts(data);
      setApiConnected(true);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Failed to connect to backend';
      setError(msg);
      setApiConnected(false);
    } finally {
      setLoading(false);
      setIsRefreshing(false);
    }
  };

  useEffect(() => {
    fetchAlerts();
  }, []);

  // Compute tier count statistics
  const tierCounts = useMemo(() => {
    const counts: Record<RiskTier | 'all', number> = {
      all: alerts.length,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
    };
    alerts.forEach((a) => {
      if (counts[a.risk_tier] !== undefined) {
        counts[a.risk_tier]++;
      }
    });
    return counts;
  }, [alerts]);

  // Filter alerts by risk tier and search query
  const filteredAlerts = useMemo(() => {
    return alerts.filter((alert) => {
      // Risk tier filter
      if (selectedTier !== 'all' && alert.risk_tier !== selectedTier) {
        return false;
      }

      // Search query filter (matches subject, from, city, country, or message_id)
      if (searchQuery.trim()) {
        const query = searchQuery.toLowerCase();
        const subjectMatch = alert.subject.toLowerCase().includes(query);
        const fromMatch = alert.from.toLowerCase().includes(query);
        const msgIdMatch = alert.message_id.toLowerCase().includes(query);
        const cityMatch = alert.geolocation?.city.toLowerCase().includes(query) || false;
        const countryMatch = alert.geolocation?.country.toLowerCase().includes(query) || false;

        return subjectMatch || fromMatch || msgIdMatch || cityMatch || countryMatch;
      }

      return true;
    });
  }, [alerts, selectedTier, searchQuery]);

  return (
    <div className="app-container">
      {/* Top Navigation Bar */}
      <header className="navbar">
        <div className="navbar-brand">
          <div className="logo-icon">
            <Shield size={22} className="shield-svg" />
          </div>
          <div className="brand-text">
            <span className="brand-title">ThreatLens</span>
            <span className="brand-badge">Module 7</span>
            <span className="brand-subtitle">AI-Powered Email Threat Detection Dashboard</span>
          </div>
        </div>

        <div className="navbar-right">
          <div className={`api-status-pill ${apiConnected ? 'connected' : 'disconnected'}`}>
            {apiConnected ? (
              <>
                <Wifi size={14} />
                <span>FastAPI Live: <code>http://localhost:8000</code></span>
              </>
            ) : (
              <>
                <WifiOff size={14} />
                <span>Backend Offline</span>
              </>
            )}
          </div>

          <button
            className={`btn-refresh ${isRefreshing ? 'spinning' : ''}`}
            onClick={() => fetchAlerts(false)}
            title="Reload alerts from backend"
          >
            <RefreshCw size={14} />
            <span>Reload</span>
          </button>
        </div>
      </header>

      {/* Main Content Area */}
      <main className="main-content">
        {/* KPI Overview Cards */}
        <StatsCards alerts={alerts} />

        {/* Global Controls & Filter Bar */}
        <FilterBar
          selectedTier={selectedTier}
          onSelectTier={setSelectedTier}
          searchQuery={searchQuery}
          onSearchChange={setSearchQuery}
          tierCounts={tierCounts}
        />

        {/* Error Notification */}
        {error && (
          <div className="error-banner">
            <AlertCircle size={20} className="error-icon" />
            <div className="error-text">
              <strong>Connection Error:</strong> {error}. Ensure FastAPI server is running on port 8000.
            </div>
            <button className="btn-retry" onClick={() => fetchAlerts(true)}>
              Retry Connection
            </button>
          </div>
        )}

        {/* Loading State */}
        {loading && (
          <div className="loading-state">
            <div className="spinner" />
            <p>Loading threat detection telemetry from FastAPI...</p>
          </div>
        )}

        {/* Dashboard Grid: Map + Alert Feed */}
        {!loading && (
          <div className="dashboard-grid">
            <section className="grid-col map-col">
              <ThreatMap
                alerts={filteredAlerts}
                selectedAlert={selectedAlert}
                onSelectAlert={setSelectedAlert}
              />
            </section>

            <section className="grid-col feed-col">
              <AlertFeed
                alerts={filteredAlerts}
                selectedAlert={selectedAlert}
                onSelectAlert={setSelectedAlert}
              />
            </section>
          </div>
        )}
      </main>

      {/* Footer */}
      <footer className="footer">
        <div className="footer-left">
          <Cpu size={14} />
          <span>ThreatLens Platform • Risk Scale: 0–100 (Weighted ML & Forensics)</span>
        </div>
        <div className="footer-right">
          <span>FastAPI Service • Leaflet Geo Telemetry • React 19 Frontend</span>
        </div>
      </footer>

      {/* Detail Modal */}
      <AlertDetailModal
        alert={selectedAlert}
        onClose={() => setSelectedAlert(null)}
      />
    </div>
  );
}
