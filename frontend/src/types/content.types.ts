/**
 * Type definitions for Content Library components
 */

export interface CategoryCount {
  name: string;
  count: number;
  percentage: number;
}

export interface PlatformStatistics {
  name: string;
  version: string;
  ruleCount: number;
  categories: CategoryCount[];
  frameworks: string[];
  coverage: number;
}

export interface PlatformStatisticsResponse {
  platforms: PlatformStatistics[];
  total_platforms: number;
  total_rules_analyzed: number;
  source?: string;
}

export interface ContentLibraryFilters {
  search: string;
  frameworks: string[];
  categories: string[];
  platforms: string[];
  severities: string[];
}

export interface RuleBrowserState {
  isOpen: boolean;
  selectedPlatform?: PlatformStatistics;
  filters: ContentLibraryFilters;
}
