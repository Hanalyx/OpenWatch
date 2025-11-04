import { useState, useEffect } from 'react';
import { PlatformStatistics, PlatformStatisticsResponse } from '../types/content.types';

interface UseComplianceStatisticsReturn {
  platforms: PlatformStatistics[];
  loading: boolean;
  error: string | null;
  refetch: () => Promise<void>;
  totalPlatforms: number;
  totalRulesAnalyzed: number;
  source?: string;
}

export const useComplianceStatistics = (): UseComplianceStatisticsReturn => {
  const [platforms, setPlatforms] = useState<PlatformStatistics[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [totalPlatforms, setTotalPlatforms] = useState(0);
  const [totalRulesAnalyzed, setTotalRulesAnalyzed] = useState(0);
  const [source, setSource] = useState<string>();

  const fetchPlatformStatistics = async () => {
    try {
      setLoading(true);
      setError(null);

      // Use MongoDB compliance rules API endpoint
      const response = await fetch('/api/v1/compliance-rules/?view_mode=platform_statistics');

      if (!response.ok) {
        console.warn('Platform statistics endpoint not available, using fallback data');
        throw new Error(`API endpoint not available (${response.status})`);
      }

      const result: { success: boolean; data: PlatformStatisticsResponse; message: string } =
        await response.json();

      if (!result.success) {
        throw new Error('API returned unsuccessful response');
      }

      const {
        platforms: platformData,
        total_platforms,
        total_rules_analyzed,
        source: dataSource,
      } = result.data;

      setPlatforms(platformData);
      setTotalPlatforms(total_platforms);
      setTotalRulesAnalyzed(total_rules_analyzed);
      setSource(dataSource);
    } catch (err) {
      const errorMessage =
        err instanceof Error ? err.message : 'Failed to fetch platform statistics';
      setError(errorMessage);
      console.error('Error fetching platform statistics:', err);

      // No fallback data - show actual error state
      setPlatforms([]);
      setTotalPlatforms(0);
      setTotalRulesAnalyzed(0);
      setSource(undefined);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchPlatformStatistics();
  }, []);

  return {
    platforms,
    loading,
    error,
    refetch: fetchPlatformStatistics,
    totalPlatforms,
    totalRulesAnalyzed,
    source,
  };
};
