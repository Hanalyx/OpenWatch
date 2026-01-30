/**
 * Custom Hooks Index
 *
 * Centralized export point for all custom React hooks.
 * Makes imports cleaner and more maintainable.
 *
 * @module hooks
 */

// Host management hooks
export { useHostData } from './useHostData';
export type { UseHostDataReturn } from './useHostData';

export {
  useHosts,
  useHost,
  useCreateHost,
  useUpdateHost,
  useDeleteHost,
  hostKeys,
} from './useHosts';

export { useHostFilters } from './useHostFilters';
export type { UseHostFiltersReturn, GroupedHosts } from './useHostFilters';

export { useHostSelection } from './useHostSelection';
export type { UseHostSelectionReturn } from './useHostSelection';
