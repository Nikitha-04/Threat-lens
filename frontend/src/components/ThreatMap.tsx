import React, { useEffect, useRef } from 'react';
import L from 'leaflet';
import 'leaflet/dist/leaflet.css';
import type { Alert } from '../types/alert';
import { TIER_CONFIG } from '../types/alert';
import { Globe, MapPin } from 'lucide-react';

interface ThreatMapProps {
  alerts: Alert[];
  selectedAlert: Alert | null;
  onSelectAlert: (alert: Alert) => void;
}

export const ThreatMap: React.FC<ThreatMapProps> = ({
  alerts,
  selectedAlert,
  onSelectAlert,
}) => {
  const mapContainerRef = useRef<HTMLDivElement>(null);
  const mapInstanceRef = useRef<L.Map | null>(null);
  const markersLayerRef = useRef<L.LayerGroup | null>(null);
  const markersByMsgIdRef = useRef<Map<string, L.Marker>>(new Map());

  // Initialize map once
  useEffect(() => {
    if (!mapContainerRef.current || mapInstanceRef.current) return;

    const map = L.map(mapContainerRef.current, {
      center: [20, 0],
      zoom: 2,
      minZoom: 2,
      maxZoom: 14,
      worldCopyJump: true,
      attributionControl: false,
    });

    // Dark-themed tiles for cybersecurity dashboard
    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
      maxZoom: 19,
      subdomains: 'abcd',
    }).addTo(map);

    L.control.attribution({ position: 'bottomright', prefix: '© OpenStreetMap & CARTO' }).addTo(map);

    const markersLayer = L.layerGroup().addTo(map);
    markersLayerRef.current = markersLayer;
    mapInstanceRef.current = map;

    return () => {
      map.remove();
      mapInstanceRef.current = null;
    };
  }, []);

  // Update markers when alerts change
  useEffect(() => {
    const map = mapInstanceRef.current;
    const markersLayer = markersLayerRef.current;
    if (!map || !markersLayer) return;

    markersLayer.clearLayers();
    markersByMsgIdRef.current.clear();

    const geoAlerts = alerts.filter(
      (a): a is Alert & { geolocation: NonNullable<Alert['geolocation']> } =>
        a.geolocation !== null &&
        typeof a.geolocation.lat === 'number' &&
        typeof a.geolocation.long === 'number'
    );

    geoAlerts.forEach((alert) => {
      const { lat, long, city, country } = alert.geolocation;
      const tierStyle = TIER_CONFIG[alert.risk_tier];

      // Custom pulsing circular SVG icon color-coded by risk tier
      const customIcon = L.divIcon({
        className: 'custom-threat-marker',
        html: `
          <div class="marker-pulse-wrapper" style="--marker-color: ${tierStyle.color}">
            <div class="marker-ring"></div>
            <div class="marker-core"></div>
          </div>
        `,
        iconSize: [26, 26],
        iconAnchor: [13, 13],
        popupAnchor: [0, -12],
      });

      const marker = L.marker([lat, long], { icon: customIcon });

      const popupContent = document.createElement('div');
      popupContent.className = 'threat-popup-container';
      popupContent.innerHTML = `
        <div style="font-family: system-ui, -apple-system, sans-serif; min-width: 200px;">
          <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 8px;">
            <span style="
              font-size: 11px;
              font-weight: 700;
              text-transform: uppercase;
              padding: 2px 6px;
              border-radius: 4px;
              background-color: ${tierStyle.bg};
              color: ${tierStyle.color};
              border: 1px solid ${tierStyle.border};
            ">
              ${alert.risk_tier.toUpperCase()} TIER
            </span>
            <span style="font-size: 13px; font-weight: 700; color: #f8fafc;">
              ${alert.risk_score.toFixed(1)} / 100
            </span>
          </div>
          <div style="font-size: 12px; font-weight: 600; color: #f1f5f9; margin-bottom: 4px; line-height: 1.3;">
            ${escapeHtml(alert.subject)}
          </div>
          <div style="font-size: 11px; color: #94a3b8; margin-bottom: 6px; word-break: break-all;">
            From: <strong>${escapeHtml(alert.from)}</strong>
          </div>
          <div style="font-size: 11px; color: #64748b; margin-bottom: 10px;">
            📍 ${escapeHtml(city)}, ${escapeHtml(country)} (${lat.toFixed(2)}, ${long.toFixed(2)})
          </div>
          <button id="view-alert-${alert.message_id}" style="
            width: 100%;
            padding: 6px 10px;
            font-size: 11px;
            font-weight: 600;
            color: #ffffff;
            background-color: #2563eb;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            transition: background-color 0.15s;
          ">
            Inspect Threat Details →
          </button>
        </div>
      `;

      // Attach click handler to popup button
      marker.bindPopup(popupContent, { className: 'custom-dark-popup', maxWidth: 280 });
      marker.on('popupopen', () => {
        const btn = document.getElementById(`view-alert-${alert.message_id}`);
        if (btn) {
          btn.onclick = () => {
            onSelectAlert(alert);
            marker.closePopup();
          };
        }
      });

      marker.addTo(markersLayer);
      markersByMsgIdRef.current.set(alert.message_id, marker);
    });
  }, [alerts, onSelectAlert]);

  // Handle selected alert pan / popup
  useEffect(() => {
    if (!selectedAlert || !mapInstanceRef.current) return;
    if (selectedAlert.geolocation) {
      const { lat, long } = selectedAlert.geolocation;
      mapInstanceRef.current.flyTo([lat, long], 5, { duration: 1.2 });
      const marker = markersByMsgIdRef.current.get(selectedAlert.message_id);
      if (marker) {
        marker.openPopup();
      }
    }
  }, [selectedAlert]);

  const geoCount = alerts.filter((a) => a.geolocation !== null).length;

  return (
    <div className="threat-map-wrapper">
      <div className="threat-map-header">
        <div className="map-title-group">
          <Globe className="icon-globe" size={18} />
          <span className="map-title">Global Threat Origin Map</span>
          <span className="geo-count-badge">
            <MapPin size={12} /> {geoCount} of {alerts.length} Flagged Senders Geocoded
          </span>
        </div>
        <div className="map-legend">
          <span className="legend-item"><span className="legend-dot critical"></span>Critical</span>
          <span className="legend-item"><span className="legend-dot high"></span>High</span>
          <span className="legend-item"><span className="legend-dot medium"></span>Medium</span>
          <span className="legend-item"><span className="legend-dot low"></span>Low</span>
        </div>
      </div>
      <div ref={mapContainerRef} className="threat-map-container" />
    </div>
  );
};

function escapeHtml(text: string): string {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}
