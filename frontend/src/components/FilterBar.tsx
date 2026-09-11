import React from 'react';
import type { RiskTier } from '../types/alert';
import { TIER_CONFIG } from '../types/alert';
import { Filter, Search, X } from 'lucide-react';

interface FilterBarProps {
  selectedTier: RiskTier | 'all';
  onSelectTier: (tier: RiskTier | 'all') => void;
  searchQuery: string;
  onSearchChange: (q: string) => void;
  tierCounts: Record<RiskTier | 'all', number>;
}

export const FilterBar: React.FC<FilterBarProps> = ({
  selectedTier,
  onSelectTier,
  searchQuery,
  onSearchChange,
  tierCounts,
}) => {
  const tiers: (RiskTier | 'all')[] = ['all', 'critical', 'high', 'medium', 'low'];

  return (
    <div className="filter-bar-container">
      <div className="filter-chips-group">
        <div className="filter-label">
          <Filter size={15} />
          <span>Tier:</span>
        </div>

        {tiers.map((tier) => {
          const isActive = selectedTier === tier;
          const count = tierCounts[tier] || 0;

          if (tier === 'all') {
            return (
              <button
                key="all"
                className={`filter-btn ${isActive ? 'active-all' : ''}`}
                onClick={() => onSelectTier('all')}
              >
                All Tiers
                <span className="count-pill">{count}</span>
              </button>
            );
          }

          const style = TIER_CONFIG[tier];

          return (
            <button
              key={tier}
              className={`filter-btn ${isActive ? 'active-tier' : ''}`}
              style={{
                borderColor: isActive ? style.color : undefined,
                backgroundColor: isActive ? style.bg : undefined,
                color: isActive ? style.color : undefined,
              }}
              onClick={() => onSelectTier(tier)}
            >
              <span
                className="filter-dot"
                style={{ backgroundColor: style.color }}
              />
              {style.label}
              <span className="count-pill">{count}</span>
            </button>
          );
        })}
      </div>

      <div className="search-box-wrapper">
        <Search size={15} className="search-icon" />
        <input
          type="text"
          placeholder="Filter by sender, subject, city, or message ID..."
          value={searchQuery}
          onChange={(e) => onSearchChange(e.target.value)}
          className="search-input"
        />
        {searchQuery && (
          <button
            className="search-clear-btn"
            onClick={() => onSearchChange('')}
            title="Clear search"
          >
            <X size={14} />
          </button>
        )}
      </div>
    </div>
  );
};
