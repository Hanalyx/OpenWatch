/**
 * React Query hooks for framework discovery
 */

import { useQuery } from '@tanstack/react-query';
import { frameworkService } from '@/services/frameworkService';

/**
 * Fetch list of all frameworks
 */
export const useFrameworks = () => {
  return useQuery({
    queryKey: ['frameworks'],
    queryFn: () => frameworkService.listFrameworks(),
    staleTime: 5 * 60 * 1000, // 5 minutes
  });
};

/**
 * Fetch framework details for a specific version
 */
export const useFrameworkDetails = (framework: string, version: string) => {
  return useQuery({
    queryKey: ['framework', framework, version],
    queryFn: () => frameworkService.getFrameworkDetails(framework, version),
    enabled: !!framework && !!version,
  });
};

/**
 * Fetch variable definitions for a framework version
 */
export const useFrameworkVariables = (framework: string, version: string) => {
  return useQuery({
    queryKey: ['framework-variables', framework, version],
    queryFn: () => frameworkService.getVariables(framework, version),
    enabled: !!framework && !!version,
  });
};
