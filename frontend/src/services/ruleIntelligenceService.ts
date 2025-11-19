import { type Rule } from '../store/slices/ruleSlice';

export interface RuleRecommendation {
  rule: Rule;
  score: number;
  reasons: string[];
  category:
    | 'security_priority'
    | 'platform_match'
    | 'baseline_gap'
    | 'dependency_related'
    | 'usage_pattern';
  confidence: 'high' | 'medium' | 'low';
}

export interface RuleIntelligenceAnalysis {
  recommendations: RuleRecommendation[];
  insights: {
    coverage_gaps: string[];
    priority_areas: string[];
    platform_specific_suggestions: string[];
    dependency_chains: string[];
  };
  statistics: {
    total_rules_analyzed: number;
    high_priority_count: number;
    platform_coverage: number;
    baseline_compliance: number;
  };
  timestamp: string;
}

export interface CacheEntry<T> {
  data: T;
  timestamp: number;
  expiry: number;
  key: string;
}

/**
 * Scan result data from existing scans
 * Contains rule evaluation results and metadata
 */
export interface ScanResultData {
  rule_id: string;
  result: 'pass' | 'fail' | 'error' | 'notapplicable' | 'notchecked';
  severity?: string;
  [key: string]: unknown;
}

/**
 * Analysis context for rule recommendation
 * Provides environmental and preference data for scoring
 */
interface AnalysisContext {
  currentPlatform?: string;
  targetEnvironment?: 'production' | 'staging' | 'development';
  securityBaseline?: string;
  existingScanResults?: ScanResultData[];
  userPreferences?: {
    prioritySeverities?: string[];
    preferredFrameworks?: string[];
    avoidedCategories?: string[];
  };
}

/**
 * Usage statistics response structure
 * Contains aggregated rule usage and distribution metrics
 */
interface RuleUsageStatistics {
  most_common_categories: Array<{ category: string; count: number }>;
  severity_distribution: Record<string, number>;
  framework_coverage: Record<string, number>;
  platform_support: Record<string, number>;
}

class RuleIntelligenceService {
  // Cache stores union of possible cached types for flexibility
  private cache = new Map<string, CacheEntry<RuleIntelligenceAnalysis | RuleUsageStatistics>>();
  private readonly CACHE_TTL = 5 * 60 * 1000; // 5 minutes
  private readonly MAX_CACHE_SIZE = 100;

  /**
   * Generate cache key from parameters
   * Accepts Record with unknown values for flexible parameter types
   */
  private generateCacheKey(prefix: string, params: Record<string, unknown>): string {
    const sortedParams = Object.keys(params)
      .sort()
      .map((key) => `${key}:${JSON.stringify(params[key])}`)
      .join('|');
    return `${prefix}:${btoa(sortedParams)}`;
  }

  // Cache management
  private setCache<T>(key: string, data: T, customTTL?: number): void {
    const now = Date.now();
    const expiry = now + (customTTL || this.CACHE_TTL);

    // Evict oldest entries if cache is full
    if (this.cache.size >= this.MAX_CACHE_SIZE) {
      const oldestKey = Array.from(this.cache.entries()).sort(
        ([, a], [, b]) => a.timestamp - b.timestamp
      )[0][0];
      this.cache.delete(oldestKey);
    }

    this.cache.set(key, {
      data,
      timestamp: now,
      expiry,
      key,
    });
  }

  private getCache<T>(key: string): T | null {
    const entry = this.cache.get(key);
    if (!entry) return null;

    const now = Date.now();
    if (now > entry.expiry) {
      this.cache.delete(key);
      return null;
    }

    return entry.data as T;
  }

  // Clear cache
  public clearCache(): void {
    this.cache.clear();
  }

  // Clear expired cache entries
  public clearExpiredCache(): void {
    const now = Date.now();
    Array.from(this.cache.entries()).forEach(([key, entry]) => {
      if (now > entry.expiry) {
        this.cache.delete(key);
      }
    });
  }

  /**
   * Generate rule recommendations based on various factors
   * Analyzes available rules and provides intelligent suggestions
   */
  public async generateRecommendations(params: {
    availableRules: Rule[];
    currentPlatform?: string;
    targetEnvironment?: 'production' | 'staging' | 'development';
    securityBaseline?: string;
    existingScanResults?: ScanResultData[];
    userPreferences?: {
      prioritySeverities?: string[];
      preferredFrameworks?: string[];
      avoidedCategories?: string[];
    };
  }): Promise<RuleIntelligenceAnalysis> {
    const cacheKey = this.generateCacheKey('recommendations', params);
    const cached = this.getCache<RuleIntelligenceAnalysis>(cacheKey);

    if (cached) {
      // Returning cached rule intelligence recommendations for performance
      return cached;
    }

    const {
      availableRules,
      currentPlatform,
      targetEnvironment = 'production',
      securityBaseline = 'nist',
      existingScanResults = [],
      userPreferences = {},
    } = params;

    const recommendations: RuleRecommendation[] = [];
    // Reserved for future insight generation feature
    // Will be used to provide coverage gap analysis and priority recommendations
    const _insights = {
      coverage_gaps: [] as string[],
      priority_areas: [] as string[],
      platform_specific_suggestions: [] as string[],
      dependency_chains: [] as string[],
    };

    // Analyze each rule and generate recommendations
    for (const rule of availableRules) {
      const recommendation = this.analyzeRule(rule, {
        currentPlatform,
        targetEnvironment,
        securityBaseline,
        existingScanResults,
        userPreferences,
      });

      if (recommendation && recommendation.score > 0.3) {
        // Only recommend rules with score > 30%
        recommendations.push(recommendation);
      }
    }

    // Sort recommendations by score (highest first)
    recommendations.sort((a, b) => b.score - a.score);

    // Generate insights based on analysis
    const coverageGaps = this.identifyCoverageGaps(availableRules, currentPlatform);
    const priorityAreas = this.identifyPriorityAreas(recommendations);
    const platformSuggestions = this.generatePlatformSuggestions(availableRules, currentPlatform);
    const dependencyChains = this.analyzeDependencyChains(recommendations);

    const analysis: RuleIntelligenceAnalysis = {
      recommendations: recommendations.slice(0, 20), // Top 20 recommendations
      insights: {
        coverage_gaps: coverageGaps,
        priority_areas: priorityAreas,
        platform_specific_suggestions: platformSuggestions,
        dependency_chains: dependencyChains,
      },
      statistics: {
        total_rules_analyzed: availableRules.length,
        high_priority_count: availableRules.filter((r) => r.severity === 'high').length,
        platform_coverage: this.calculatePlatformCoverage(availableRules, currentPlatform),
        baseline_compliance: this.calculateBaselineCompliance(availableRules, securityBaseline),
      },
      timestamp: new Date().toISOString(),
    };

    // Cache the result
    this.setCache(cacheKey, analysis);

    return analysis;
  }

  /**
   * Analyze individual rule for recommendation
   * Scores rule based on context and generates recommendation with reasons
   */
  private analyzeRule(rule: Rule, context: AnalysisContext): RuleRecommendation | null {
    let score = 0;
    const reasons: string[] = [];
    let category: RuleRecommendation['category'] = 'usage_pattern';
    let confidence: RuleRecommendation['confidence'] = 'medium';

    // Security priority scoring
    if (rule.severity === 'high') {
      score += 0.4;
      reasons.push('High security priority');
      category = 'security_priority';
      confidence = 'high';
    } else if (rule.severity === 'medium') {
      score += 0.25;
      reasons.push('Medium security priority');
    } else if (rule.severity === 'low') {
      score += 0.1;
      reasons.push('Low security impact');
    }

    // Platform match scoring
    if (context.currentPlatform && rule.platform_implementations?.[context.currentPlatform]) {
      score += 0.3;
      reasons.push(`Optimized for ${context.currentPlatform}`);
      category = 'platform_match';
      confidence = 'high';
    }

    // Framework alignment scoring
    if (context.securityBaseline && rule.frameworks?.[context.securityBaseline]) {
      score += 0.2;
      reasons.push(`Aligns with ${context.securityBaseline.toUpperCase()} framework`);
    }

    // User preferences
    if (context.userPreferences?.prioritySeverities?.includes(rule.severity)) {
      score += 0.15;
      reasons.push('Matches your severity preferences');
    }

    if (
      context.userPreferences?.preferredFrameworks?.some((framework: string) =>
        Object.keys(rule.frameworks || {}).includes(framework)
      )
    ) {
      score += 0.1;
      reasons.push('Matches your framework preferences');
    }

    if (context.userPreferences?.avoidedCategories?.includes(rule.category)) {
      score -= 0.2;
      reasons.push('Category marked as avoided in preferences');
    }

    // Dependency scoring
    if (rule.dependencies) {
      const depCount = rule.dependencies.requires.length + rule.dependencies.related.length;
      if (depCount > 0) {
        score += Math.min(depCount * 0.05, 0.15);
        reasons.push(`Part of ${depCount} rule dependency chain`);
        category = 'dependency_related';
      }
    }

    // Environment scoring
    if (context.targetEnvironment === 'production') {
      if (rule.severity === 'high' && rule.category.includes('security')) {
        score += 0.1;
        reasons.push('Critical for production security');
      }
    }

    // Only return recommendation if score is meaningful
    if (score < 0.1) {
      return null;
    }

    return {
      rule,
      score: Math.min(score, 1.0), // Cap at 100%
      reasons,
      category,
      confidence,
    };
  }

  // Identify coverage gaps
  private identifyCoverageGaps(rules: Rule[], platform?: string): string[] {
    const gaps: string[] = [];
    const categories = new Set(rules.map((r) => r.category));
    const expectedCategories = [
      'authentication',
      'network_security',
      'access_control',
      'system_hardening',
      'logging_monitoring',
    ];

    expectedCategories.forEach((expected) => {
      if (!categories.has(expected)) {
        gaps.push(`Missing ${expected.replace('_', ' ')} rules`);
      }
    });

    if (platform) {
      const platformRules = rules.filter((r) => r.platform_implementations?.[platform]);
      if (platformRules.length < rules.length * 0.5) {
        gaps.push(`Limited ${platform} platform coverage`);
      }
    }

    return gaps;
  }

  // Identify priority areas
  private identifyPriorityAreas(recommendations: RuleRecommendation[]): string[] {
    const categoryCount = new Map<string, number>();

    recommendations.forEach((rec) => {
      const category = rec.rule.category;
      categoryCount.set(category, (categoryCount.get(category) || 0) + rec.score);
    });

    return Array.from(categoryCount.entries())
      .sort(([, a], [, b]) => b - a)
      .slice(0, 5)
      .map(([category]) => category.replace('_', ' '));
  }

  // Generate platform-specific suggestions
  private generatePlatformSuggestions(rules: Rule[], platform?: string): string[] {
    const suggestions: string[] = [];

    if (!platform) {
      suggestions.push('Consider specifying your platform for more targeted recommendations');
      return suggestions;
    }

    const platformRules = rules.filter((r) => r.platform_implementations?.[platform]);
    const totalRules = rules.length;
    const coverage = platformRules.length / totalRules;

    if (coverage < 0.3) {
      suggestions.push(`Low ${platform} coverage - consider platform-specific security content`);
    }

    // Check for missing essential categories on the platform
    const platformCategories = new Set(platformRules.map((r) => r.category));
    if (!platformCategories.has('authentication')) {
      suggestions.push(`Add authentication rules for ${platform}`);
    }
    if (!platformCategories.has('network_security')) {
      suggestions.push(`Enhance network security rules for ${platform}`);
    }

    return suggestions;
  }

  // Analyze dependency chains
  private analyzeDependencyChains(recommendations: RuleRecommendation[]): string[] {
    const chains: string[] = [];
    const ruleMap = new Map(recommendations.map((rec) => [rec.rule.rule_id, rec.rule]));

    recommendations.forEach((rec) => {
      if (rec.rule.dependencies?.requires.length) {
        const dependsOn = rec.rule.dependencies.requires.filter((dep) => ruleMap.has(dep));
        if (dependsOn.length > 0) {
          chains.push(
            `${rec.rule.metadata.name} requires ${dependsOn.length} other recommended rules`
          );
        }
      }
    });

    return chains.slice(0, 5);
  }

  // Calculate platform coverage percentage
  private calculatePlatformCoverage(rules: Rule[], platform?: string): number {
    if (!platform) return 0;

    const platformRules = rules.filter((r) => r.platform_implementations?.[platform]);
    return Math.round((platformRules.length / rules.length) * 100);
  }

  // Calculate baseline compliance percentage
  private calculateBaselineCompliance(rules: Rule[], baseline: string): number {
    const baselineRules = rules.filter((r) => r.frameworks?.[baseline]);
    return Math.round((baselineRules.length / rules.length) * 100);
  }

  /**
   * Get rule usage statistics
   * Aggregates and analyzes rule distribution across categories, severity, frameworks
   */
  public async getRuleUsageStatistics(rules: Rule[]): Promise<RuleUsageStatistics> {
    const cacheKey = this.generateCacheKey('usage-stats', { rules: rules.map((r) => r.rule_id) });
    const cached = this.getCache<RuleUsageStatistics>(cacheKey);

    if (cached) {
      return cached;
    }

    const categoryCount = new Map<string, number>();
    const severityCount = new Map<string, number>();
    const frameworkCount = new Map<string, number>();
    const platformCount = new Map<string, number>();

    rules.forEach((rule) => {
      // Categories
      categoryCount.set(rule.category, (categoryCount.get(rule.category) || 0) + 1);

      // Severities
      severityCount.set(rule.severity, (severityCount.get(rule.severity) || 0) + 1);

      // Frameworks
      Object.keys(rule.frameworks || {}).forEach((framework) => {
        frameworkCount.set(framework, (frameworkCount.get(framework) || 0) + 1);
      });

      // Platforms
      Object.keys(rule.platform_implementations || {}).forEach((platform) => {
        platformCount.set(platform, (platformCount.get(platform) || 0) + 1);
      });
    });

    const stats = {
      most_common_categories: Array.from(categoryCount.entries())
        .map(([category, count]) => ({ category, count }))
        .sort((a, b) => b.count - a.count),
      severity_distribution: Object.fromEntries(severityCount),
      framework_coverage: Object.fromEntries(frameworkCount),
      platform_support: Object.fromEntries(platformCount),
    };

    this.setCache(cacheKey, stats);
    return stats;
  }

  // Get cache statistics
  public getCacheStatistics() {
    const now = Date.now();
    const entries = Array.from(this.cache.values());
    const expired = entries.filter((entry) => now > entry.expiry).length;

    return {
      total_entries: this.cache.size,
      expired_entries: expired,
      cache_hit_potential: Math.round(((this.cache.size - expired) / this.MAX_CACHE_SIZE) * 100),
      memory_usage_estimate: `~${Math.round(this.cache.size * 0.5)}KB`, // Rough estimate
    };
  }
}

// Singleton instance
export const ruleIntelligenceService = new RuleIntelligenceService();
