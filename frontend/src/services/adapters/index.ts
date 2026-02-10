/**
 * API Response Adapters
 *
 * Centralizes snake_case (backend) to camelCase (frontend) transformations.
 * Import adapters from this barrel file:
 *
 *   import { adaptHosts, toCreateHostRequest } from '../services/adapters';
 *
 * @module services/adapters
 */

export {
  adaptHost,
  adaptHosts,
  adaptConnectionTest,
  adaptCredential,
  adaptKeyValidation,
  toCreateHostRequest,
  toUpdateHostRequest,
} from './hostAdapter';

export type {
  ApiHostResponse,
  ApiConnectionTestResponse,
  ApiCredentialResponse,
  ApiKeyValidationResponse,
  ApiHostCreateRequest,
  ApiHostUpdateRequest,
  ConnectionTestResult,
  SystemCredential,
  KeyValidationResult,
} from './hostAdapter';

export { adaptRuleResult, adaptRuleResults } from './scanAdapter';

export type {
  ApiScanResponse,
  ApiScanResults,
  ApiRuleResult,
  RuleResult,
  RuleSeverity,
  RuleOutcome,
} from './scanAdapter';

export { adaptComplianceRule, adaptComplianceRulesPage } from './complianceAdapter';

export type {
  ApiComplianceRule,
  ApiComplianceRulesPage,
  ApiFrameworkDetail,
  ApiComplianceTemplate,
  ComplianceRule,
  ComplianceRulesPage,
} from './complianceAdapter';

// Host Detail adapters for Host Detail page redesign
export {
  fetchComplianceState,
  fetchHostSchedule,
  fetchSchedulerStatus,
  fetchSystemInfo,
  fetchIntelligenceSummary,
  fetchPackages,
  fetchServices,
  fetchUsers,
  fetchNetwork,
  fetchFirewall,
  fetchRoutes,
  fetchScanHistory,
} from './hostDetailAdapter';
