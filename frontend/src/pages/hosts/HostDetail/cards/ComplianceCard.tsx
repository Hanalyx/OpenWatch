/**
 * Compliance Summary Card
 *
 * Displays compliance score, pass/fail counts, and critical findings
 * from the most recent Aegis scan.
 *
 * Part of OpenWatch OS Transformation - Host Detail Page Redesign.
 *
 * @module pages/hosts/HostDetail/cards/ComplianceCard
 */

import React from 'react';
import { Box, Card, CardContent, Typography, Skeleton } from '@mui/material';
import type { ComplianceState } from '../../../../types/hostDetail';

interface ComplianceCardProps {
  complianceState: ComplianceState | null | undefined;
  isLoading?: boolean;
}

/**
 * Get color based on compliance score
 */
function getScoreColor(score: number): string {
  if (score >= 80) return 'success.main';
  if (score >= 60) return 'warning.main';
  return 'error.main';
}

/**
 * Get text label for compliance state
 */
function getComplianceLabel(score: number): string {
  if (score >= 90) return 'Compliant';
  if (score >= 80) return 'Mostly Compliant';
  if (score >= 60) return 'Partial';
  if (score >= 40) return 'Low';
  return 'Critical';
}

const ComplianceCard: React.FC<ComplianceCardProps> = ({ complianceState, isLoading }) => {
  if (isLoading) {
    return (
      <Card sx={{ height: '100%', minHeight: 180 }}>
        <CardContent>
          <Skeleton variant="text" width="40%" height={24} sx={{ mb: 2 }} />
          <Skeleton variant="text" width="60%" height={48} sx={{ mb: 1 }} />
          <Skeleton variant="text" width="80%" height={20} />
          <Skeleton variant="text" width="70%" height={20} />
        </CardContent>
      </Card>
    );
  }

  const hasData = complianceState && complianceState.totalRules > 0;

  return (
    <Card sx={{ height: '100%', minHeight: 180 }}>
      <CardContent>
        <Typography variant="body2" color="text.secondary" gutterBottom>
          Compliance
        </Typography>

        {hasData ? (
          <>
            <Box sx={{ display: 'flex', alignItems: 'baseline', gap: 1, mb: 1 }}>
              <Typography
                variant="h3"
                component="span"
                color={getScoreColor(complianceState.complianceScore)}
                fontWeight="bold"
              >
                {complianceState.complianceScore.toFixed(0)}%
              </Typography>
              <Typography variant="body2" color="text.secondary">
                {getComplianceLabel(complianceState.complianceScore)}
              </Typography>
            </Box>

            <Box sx={{ display: 'flex', gap: 2, mb: 1 }}>
              <Typography variant="body2">
                <Typography component="span" color="success.main" fontWeight="medium">
                  {complianceState.passed}
                </Typography>
                {' passed'}
              </Typography>
              <Typography variant="body2">
                <Typography component="span" color="error.main" fontWeight="medium">
                  {complianceState.failed}
                </Typography>
                {' failed'}
              </Typography>
            </Box>

            {complianceState.severitySummary.critical.failed > 0 && (
              <Typography variant="body2" color="error.main">
                {complianceState.severitySummary.critical.failed} critical findings
              </Typography>
            )}

            {complianceState.scanDate && (
              <Typography variant="caption" color="text.secondary" display="block" sx={{ mt: 1 }}>
                Last scan: {new Date(complianceState.scanDate).toLocaleDateString()}
              </Typography>
            )}
          </>
        ) : (
          <Typography variant="body2" color="text.secondary">
            No compliance data available. Awaiting first scan.
          </Typography>
        )}
      </CardContent>
    </Card>
  );
};

export default ComplianceCard;
