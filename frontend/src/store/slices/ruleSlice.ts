import { createSlice, createAsyncThunk, PayloadAction } from '@reduxjs/toolkit';
import { api } from '../../services/api';

// Types
export interface Rule {
  rule_id: string;
  scap_rule_id: string;
  metadata: {
    name: string;
    description: string;
    rationale: string;
    source: string;
  };
  abstract: boolean;
  severity: 'high' | 'medium' | 'low' | 'info';
  category: string;
  security_function: string;
  tags: string[];
  frameworks: {
    [key: string]: {
      [version: string]: string[];
    };
  };
  platform_implementations: {
    [platform: string]: {
      versions: string[];
      check_command: string;
      enable_command: string;
      config_files?: string[];
    };
  };
  dependencies: {
    requires: string[];
    conflicts: string[];
    related: string[];
  };
  created_at: string;
  updated_at: string;
  // Enhanced fields from Phase 4
  inheritance?: {
    parent_rule: string | null;
    overridden_parameters: string[];
    inherited_frameworks: string[];
  };
  parameter_overrides?: {
    [key: string]: any;
  };
  relevance_score?: number;
  matched_fields?: string[];
}

export interface FilterState {
  platforms: string[];
  severities: string[];
  categories: string[];
  frameworks: string[];
  tags: string[];
  abstract: boolean | null;
}

export interface SearchRequest {
  query: string;
  filters?: {
    platform?: string[];
    severity?: string[];
    category?: string[];
    framework?: string[];
    tag?: string[];
  };
  sort_by?: 'relevance' | 'severity' | 'name' | 'updated';
  limit?: number;
  offset?: number;
}

export interface PlatformCapability {
  platform: string;
  platform_version: string;
  detection_timestamp: string;
  target_host?: string;
  capabilities: {
    [type: string]: {
      detected: boolean;
      results: any;
    };
  };
  baseline_comparison?: {
    missing: string[];
    matched: string[];
    analysis: {
      baseline_coverage: number;
      platform_health: string;
    };
  };
}

export interface RuleDependencyGraph {
  rule_id: string;
  dependency_graph: {
    direct_dependencies: {
      requires: string[];
      conflicts: string[];
      related: string[];
    };
    transitive_dependencies?: {
      [rule_id: string]: {
        requires: string[];
        depth: number;
      };
    };
  };
  conflict_analysis: {
    has_conflicts: boolean;
    conflict_details: Array<{
      conflicting_rule: string;
      reason: string;
    }>;
  };
  dependency_count: number;
}

interface RuleState {
  rules: Rule[];
  filteredRules: Rule[];
  selectedRule: Rule | null;
  searchQuery: string;
  searchResults: Rule[];
  activeFilters: FilterState;
  viewMode: 'grid' | 'list' | 'tree';
  isLoading: boolean;
  isSearching: boolean;
  error: string | null;
  cache: {
    lastUpdated: string | null;
    isStale: boolean;
  };
  pagination: {
    offset: number;
    limit: number;
    totalCount: number;
    hasNext: boolean;
    hasPrev: boolean;
  };
  platformCapabilities: PlatformCapability | null;
  ruleDependencies: RuleDependencyGraph | null;
  availablePlatforms: string[];
  availableCategories: string[];
  availableFrameworks: string[];
}

const initialState: RuleState = {
  rules: [],
  filteredRules: [],
  selectedRule: null,
  searchQuery: '',
  searchResults: [],
  activeFilters: {
    platforms: [],
    severities: [],
    categories: [],
    frameworks: [],
    tags: [],
    abstract: null,
  },
  viewMode: 'grid',
  isLoading: false,
  isSearching: false,
  error: null,
  cache: {
    lastUpdated: null,
    isStale: true,
  },
  pagination: {
    offset: 0,
    limit: 50,
    totalCount: 0,
    hasNext: false,
    hasPrev: false,
  },
  platformCapabilities: null,
  ruleDependencies: null,
  availablePlatforms: [],
  availableCategories: [],
  availableFrameworks: [],
};

// Async thunks
export const fetchRules = createAsyncThunk(
  'rules/fetchRules',
  async (
    params: {
      offset?: number;
      limit?: number;
      platform?: string;
      severity?: string;
      category?: string;
      framework?: string;
      abstract?: boolean;
    } = {}
  ) => {
    const queryParams = new URLSearchParams();
    Object.entries(params).forEach(([key, value]) => {
      if (value !== undefined) {
        queryParams.append(key, value.toString());
      }
    });

    const response = await api.get(`/api/rules?${queryParams.toString()}`);
    return response.data;
  }
);

export const searchRules = createAsyncThunk(
  'rules/searchRules',
  async (searchRequest: SearchRequest) => {
    const response = await api.post('/api/rules/search', searchRequest);
    return response.data;
  }
);

export const fetchRuleDetails = createAsyncThunk(
  'rules/fetchRuleDetails',
  async ({ ruleId, includeInheritance }: { ruleId: string; includeInheritance?: boolean }) => {
    const params = includeInheritance ? '?include_inheritance=true' : '';
    const response = await api.get(`/api/rules/${ruleId}${params}`);
    return response.data;
  }
);

export const fetchRuleDependencies = createAsyncThunk(
  'rules/fetchRuleDependencies',
  async ({
    ruleIds,
    includeTransitive = true,
    maxDepth = 5,
  }: {
    ruleIds: string[];
    includeTransitive?: boolean;
    maxDepth?: number;
  }) => {
    const response = await api.post('/api/rules/dependencies', {
      rule_ids: ruleIds,
      include_transitive: includeTransitive,
      max_depth: maxDepth,
    });
    return response.data;
  }
);

export const detectPlatformCapabilities = createAsyncThunk(
  'rules/detectPlatformCapabilities',
  async (params: {
    platform: string;
    platformVersion: string;
    targetHost?: string;
    compareBaseline?: boolean;
    capabilityTypes?: string[];
  }) => {
    const response = await api.post('/api/rules/platform-capabilities', {
      platform: params.platform,
      platform_version: params.platformVersion,
      target_host: params.targetHost,
      compare_baseline: params.compareBaseline ?? true,
      capability_types: params.capabilityTypes ?? ['package', 'service', 'security'],
    });
    return response.data;
  }
);

export const exportRules = createAsyncThunk(
  'rules/exportRules',
  async ({
    ruleIds,
    format,
    includeMetadata = true,
  }: {
    ruleIds: string[];
    format: 'json' | 'csv' | 'xml';
    includeMetadata?: boolean;
  }) => {
    const response = await api.post('/api/rules/export', {
      rule_ids: ruleIds,
      format,
      include_metadata: includeMetadata,
    });
    return response;
  }
);

// Slice
const ruleSlice = createSlice({
  name: 'rules',
  initialState,
  reducers: {
    selectRule: (state, action: PayloadAction<Rule | null>) => {
      state.selectedRule = action.payload;
    },
    setViewMode: (state, action: PayloadAction<'grid' | 'list' | 'tree'>) => {
      state.viewMode = action.payload;
    },
    setSearchQuery: (state, action: PayloadAction<string>) => {
      state.searchQuery = action.payload;
    },
    updateFilters: (state, action: PayloadAction<Partial<FilterState>>) => {
      state.activeFilters = {
        ...state.activeFilters,
        ...action.payload,
      };
    },
    clearFilters: (state) => {
      state.activeFilters = initialState.activeFilters;
      state.filteredRules = state.rules;
    },
    setPagination: (state, action: PayloadAction<{ offset: number; limit: number }>) => {
      state.pagination.offset = action.payload.offset;
      state.pagination.limit = action.payload.limit;
    },
    clearError: (state) => {
      state.error = null;
    },
    updateCache: (state, action: PayloadAction<{ lastUpdated: string; isStale: boolean }>) => {
      state.cache = action.payload;
    },
  },
  extraReducers: (builder) => {
    builder
      // Fetch Rules
      .addCase(fetchRules.pending, (state) => {
        state.isLoading = true;
        state.error = null;
      })
      .addCase(fetchRules.fulfilled, (state, action) => {
        state.isLoading = false;
        if (action.payload.success && action.payload.data) {
          state.rules = action.payload.data.rules || [];
          state.filteredRules = state.rules;
          state.pagination = {
            offset: action.payload.data.offset || 0,
            limit: action.payload.data.limit || 50,
            totalCount: action.payload.data.total_count || 0,
            hasNext: action.payload.data.has_next || false,
            hasPrev: action.payload.data.has_prev || false,
          };
          state.cache = {
            lastUpdated: new Date().toISOString(),
            isStale: false,
          };

          // Extract unique values for filters
          const platforms = new Set<string>();
          const categories = new Set<string>();
          const frameworks = new Set<string>();

          state.rules.forEach((rule) => {
            Object.keys(rule.platform_implementations || {}).forEach((p) => platforms.add(p));
            if (rule.category) categories.add(rule.category);
            Object.keys(rule.frameworks || {}).forEach((f) => frameworks.add(f));
          });

          state.availablePlatforms = Array.from(platforms).sort();
          state.availableCategories = Array.from(categories).sort();
          state.availableFrameworks = Array.from(frameworks).sort();
        }
      })
      .addCase(fetchRules.rejected, (state, action) => {
        state.isLoading = false;
        state.error = action.error.message || 'Failed to fetch rules';
      })

      // Search Rules
      .addCase(searchRules.pending, (state) => {
        state.isSearching = true;
        state.error = null;
      })
      .addCase(searchRules.fulfilled, (state, action) => {
        state.isSearching = false;
        if (action.payload.success && action.payload.data) {
          state.searchResults = action.payload.data.results || [];
        }
      })
      .addCase(searchRules.rejected, (state, action) => {
        state.isSearching = false;
        state.error = action.error.message || 'Failed to search rules';
      })

      // Fetch Rule Details
      .addCase(fetchRuleDetails.fulfilled, (state, action) => {
        if (action.payload.success && action.payload.data) {
          state.selectedRule = action.payload.data;
        }
      })

      // Fetch Rule Dependencies
      .addCase(fetchRuleDependencies.fulfilled, (state, action) => {
        if (action.payload.success && action.payload.data) {
          state.ruleDependencies = action.payload.data;
        }
      })

      // Platform Capabilities
      .addCase(detectPlatformCapabilities.fulfilled, (state, action) => {
        if (action.payload.success && action.payload.data) {
          state.platformCapabilities = action.payload.data;
        }
      });
  },
});

export const {
  selectRule,
  setViewMode,
  setSearchQuery,
  updateFilters,
  clearFilters,
  setPagination,
  clearError,
  updateCache,
} = ruleSlice.actions;

export default ruleSlice.reducer;
