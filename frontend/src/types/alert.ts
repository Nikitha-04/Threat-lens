export type RiskTier = 'low' | 'medium' | 'high' | 'critical';

export interface Geolocation {
  country: string;
  city: string;
  lat: number;
  long: number;
}

export interface Alert {
  message_id: string;
  subject: string;
  from: string;
  date: string;
  risk_score: number; // 0 - 100 float scale
  risk_tier: RiskTier;
  contributing_factors: string[];
  geolocation: Geolocation | null;
}

export const TIER_CONFIG: Record<
  RiskTier,
  {
    label: string;
    color: string;
    bg: string;
    border: string;
    text: string;
    glow: string;
  }
> = {
  critical: {
    label: 'Critical',
    color: '#ef4444',
    bg: 'rgba(239, 68, 68, 0.15)',
    border: 'rgba(239, 68, 68, 0.4)',
    text: '#fca5a5',
    glow: 'rgba(239, 68, 68, 0.6)',
  },
  high: {
    label: 'High',
    color: '#f97316',
    bg: 'rgba(249, 115, 22, 0.15)',
    border: 'rgba(249, 115, 22, 0.4)',
    text: '#fdba74',
    glow: 'rgba(249, 115, 22, 0.6)',
  },
  medium: {
    label: 'Medium',
    color: '#eab308',
    bg: 'rgba(234, 179, 8, 0.15)',
    border: 'rgba(234, 179, 8, 0.4)',
    text: '#fde047',
    glow: 'rgba(234, 179, 8, 0.6)',
  },
  low: {
    label: 'Low',
    color: '#22c55e',
    bg: 'rgba(34, 197, 94, 0.15)',
    border: 'rgba(34, 197, 94, 0.4)',
    text: '#86efac',
    glow: 'rgba(34, 197, 94, 0.6)',
  },
};
