/**
 * React Query hooks for template management
 */

import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { templateService } from '@/services/templateService';
import type { CreateTemplateRequest, UpdateTemplateRequest } from '@/types/scanConfig';

/**
 * Fetch list of templates with optional filters
 */
export const useTemplates = (filters?: { framework?: string; tags?: string }) => {
  return useQuery({
    queryKey: ['templates', filters],
    queryFn: () => templateService.list(filters),
  });
};

/**
 * Fetch a single template by ID
 */
export const useTemplate = (id: string) => {
  return useQuery({
    queryKey: ['template', id],
    queryFn: () => templateService.get(id),
    enabled: !!id,
  });
};

/**
 * Create a new template
 */
export const useCreateTemplate = () => {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (data: CreateTemplateRequest) => templateService.create(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['templates'] });
    },
  });
};

/**
 * Update an existing template
 */
export const useUpdateTemplate = () => {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: ({ id, data }: { id: string; data: UpdateTemplateRequest }) =>
      templateService.update(id, data),
    onSuccess: (_, variables) => {
      queryClient.invalidateQueries({ queryKey: ['templates'] });
      queryClient.invalidateQueries({ queryKey: ['template', variables.id] });
    },
  });
};

/**
 * Delete a template
 */
export const useDeleteTemplate = () => {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (id: string) => templateService.delete(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['templates'] });
    },
  });
};

/**
 * Clone a template
 */
export const useCloneTemplate = () => {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: ({ id, newName }: { id: string; newName: string }) =>
      templateService.clone(id, newName),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['templates'] });
    },
  });
};

/**
 * Set a template as default
 */
export const useSetDefaultTemplate = () => {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (id: string) => templateService.setDefault(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['templates'] });
    },
  });
};

/**
 * Fetch template statistics
 */
export const useTemplateStatistics = () => {
  return useQuery({
    queryKey: ['template-statistics'],
    queryFn: () => templateService.getStatistics(),
  });
};
