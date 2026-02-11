/**
 * Rule Reference React Query Hooks
 *
 * Provides cached, automatically-refreshing data for the Rule Reference page.
 * Uses React Query for optimal data fetching with background updates.
 *
 * Part of OpenWatch OS Transformation.
 *
 * @module hooks/useRuleReference
 */

import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  fetchRules,
  fetchRuleDetail,
  fetchRuleStatistics,
  fetchFrameworks,
  fetchCategories,
  fetchVariables,
  fetchCapabilities,
  refreshRuleCache,
} from '../services/adapters/ruleReferenceAdapter';
import type {
  RuleListResponse,
  RuleDetailResponse,
  RuleStatistics,
  FrameworkListResponse,
  CategoryListResponse,
  VariableListResponse,
  CapabilityListResponse,
  RuleSearchParams,
} from '../types/ruleReference';

// =============================================================================
// Query Keys
// =============================================================================

export const ruleReferenceKeys = {
  all: ['ruleReference'] as const,
  rules: (params?: RuleSearchParams) => ['ruleReference', 'rules', params] as const,
  ruleDetail: (ruleId: string) => ['ruleReference', 'rule', ruleId] as const,
  statistics: ['ruleReference', 'statistics'] as const,
  frameworks: ['ruleReference', 'frameworks'] as const,
  categories: ['ruleReference', 'categories'] as const,
  variables: ['ruleReference', 'variables'] as const,
  capabilities: ['ruleReference', 'capabilities'] as const,
};

// =============================================================================
// Rules List Hook
// =============================================================================

/**
 * Fetch and cache paginated list of rules with optional filtering.
 *
 * Provides rule summaries with severity, category, tags, and framework counts.
 *
 * @param params - Search and filter parameters
 * @param enabled - Whether the query should run (default: true)
 */
export function useRules(params?: RuleSearchParams, enabled: boolean = true) {
  return useQuery<RuleListResponse>({
    queryKey: ruleReferenceKeys.rules(params),
    queryFn: () => fetchRules(params),
    enabled,
    staleTime: 300_000, // 5 minutes - rules are static
    refetchOnWindowFocus: false,
  });
}

// =============================================================================
// Rule Detail Hook
// =============================================================================

/**
 * Fetch and cache detailed information for a specific rule.
 *
 * Provides full rule details including description, rationale,
 * framework references, implementations, and dependencies.
 *
 * @param ruleId - ID of the rule to fetch
 * @param enabled - Whether the query should run (default: true)
 */
export function useRuleDetail(ruleId: string | undefined, enabled: boolean = true) {
  return useQuery<RuleDetailResponse>({
    queryKey: ruleReferenceKeys.ruleDetail(ruleId!),
    queryFn: () => fetchRuleDetail(ruleId!),
    enabled: !!ruleId && enabled,
    staleTime: 300_000, // 5 minutes - rules are static
    refetchOnWindowFocus: false,
  });
}

// =============================================================================
// Statistics Hook
// =============================================================================

/**
 * Fetch and cache rule statistics.
 *
 * Provides counts by severity, category, framework, and remediation status.
 *
 * @param enabled - Whether the query should run (default: true)
 */
export function useRuleStatistics(enabled: boolean = true) {
  return useQuery<RuleStatistics>({
    queryKey: ruleReferenceKeys.statistics,
    queryFn: fetchRuleStatistics,
    enabled,
    staleTime: 300_000, // 5 minutes
    refetchOnWindowFocus: false,
  });
}

// =============================================================================
// Frameworks Hook
// =============================================================================

/**
 * Fetch and cache list of compliance frameworks.
 *
 * Provides framework info including name, description, versions, and rule counts.
 *
 * @param enabled - Whether the query should run (default: true)
 */
export function useFrameworks(enabled: boolean = true) {
  return useQuery<FrameworkListResponse>({
    queryKey: ruleReferenceKeys.frameworks,
    queryFn: fetchFrameworks,
    enabled,
    staleTime: 300_000, // 5 minutes
    refetchOnWindowFocus: false,
  });
}

// =============================================================================
// Categories Hook
// =============================================================================

/**
 * Fetch and cache list of rule categories.
 *
 * Provides category info including name, description, and rule counts.
 *
 * @param enabled - Whether the query should run (default: true)
 */
export function useCategories(enabled: boolean = true) {
  return useQuery<CategoryListResponse>({
    queryKey: ruleReferenceKeys.categories,
    queryFn: fetchCategories,
    enabled,
    staleTime: 300_000, // 5 minutes
    refetchOnWindowFocus: false,
  });
}

// =============================================================================
// Variables Hook
// =============================================================================

/**
 * Fetch and cache list of rule variables.
 *
 * Provides variable definitions including defaults, overrides, and usage.
 *
 * @param enabled - Whether the query should run (default: true)
 */
export function useVariables(enabled: boolean = true) {
  return useQuery<VariableListResponse>({
    queryKey: ruleReferenceKeys.variables,
    queryFn: fetchVariables,
    enabled,
    staleTime: 300_000, // 5 minutes
    refetchOnWindowFocus: false,
  });
}

// =============================================================================
// Capabilities Hook
// =============================================================================

/**
 * Fetch and cache list of capability probes.
 *
 * Provides capability info including detection methods and rule counts.
 *
 * @param enabled - Whether the query should run (default: true)
 */
export function useCapabilities(enabled: boolean = true) {
  return useQuery<CapabilityListResponse>({
    queryKey: ruleReferenceKeys.capabilities,
    queryFn: fetchCapabilities,
    enabled,
    staleTime: 300_000, // 5 minutes
    refetchOnWindowFocus: false,
  });
}

// =============================================================================
// Refresh Cache Mutation
// =============================================================================

/**
 * Mutation to refresh the rule cache (admin only).
 *
 * Invalidates all rule reference queries after successful refresh.
 */
export function useRefreshRuleCache() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: refreshRuleCache,
    onSuccess: () => {
      // Invalidate all rule reference queries
      queryClient.invalidateQueries({ queryKey: ruleReferenceKeys.all });
    },
  });
}

// =============================================================================
// Invalidation Hook
// =============================================================================

/**
 * Hook to invalidate all rule reference queries.
 *
 * Useful when rules are updated or cache needs to be cleared.
 */
export function useInvalidateRuleReference() {
  const queryClient = useQueryClient();

  return () => {
    queryClient.invalidateQueries({ queryKey: ruleReferenceKeys.all });
  };
}
