import { useState, useEffect } from 'react';

interface FrameworkCategory {
  name: string;
  count: number;
  percentage: number;
}

interface FrameworkData {
  name: string;
  version: string;
  ruleCount: number;
  categories: FrameworkCategory[];
  platforms: string[];
  coverage: number;
}

interface FrameworkStatistics {
  frameworks: FrameworkData[];
  total_frameworks: number;
  total_rules_analyzed: number;
  source: string;
}

interface UseFrameworkStatisticsReturn {
  frameworks: FrameworkData[];
  totalFrameworks: number;
  totalRulesAnalyzed: number;
  loading: boolean;
  error: string | null;
  refetch: () => void;
}

export const useFrameworkStatistics = (): UseFrameworkStatisticsReturn => {
  const [frameworks, setFrameworks] = useState<FrameworkData[]>([]);
  const [totalFrameworks, setTotalFrameworks] = useState(0);
  const [totalRulesAnalyzed, setTotalRulesAnalyzed] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchFrameworkStatistics = async () => {
    try {
      setLoading(true);
      setError(null);

      // Use MongoDB compliance rules API endpoint
      const response = await fetch('/api/v1/compliance-rules/?view_mode=framework_statistics');

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      const result = await response.json();

      if (!result.success) {
        throw new Error(result.message || 'Failed to fetch framework statistics');
      }

      const data: FrameworkStatistics = result.data;

      setFrameworks(data.frameworks || []);
      setTotalFrameworks(data.total_frameworks || 0);
      setTotalRulesAnalyzed(data.total_rules_analyzed || 0);
    } catch (err) {
      console.error('Error fetching framework statistics:', err);
      setError(err instanceof Error ? err.message : 'Unknown error occurred');

      // Clear data on error
      setFrameworks([]);
      setTotalFrameworks(0);
      setTotalRulesAnalyzed(0);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchFrameworkStatistics();
  }, []);

  const refetch = () => {
    fetchFrameworkStatistics();
  };

  return {
    frameworks,
    totalFrameworks,
    totalRulesAnalyzed,
    loading,
    error,
    refetch,
  };
};
