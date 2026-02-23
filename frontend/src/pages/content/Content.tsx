/**
 * Content Page
 *
 * Entry point for the Rule Reference feature. Provides access to Kensa
 * compliance rules with browsing, filtering, and detailed information.
 *
 * Part of OpenWatch OS Transformation - replaces MongoDB-based Content Library.
 *
 * @module pages/content/Content
 */

import React from 'react';
import { Box } from '@mui/material';
import RuleReference from './RuleReference';

const Content: React.FC = () => {
  return (
    <Box sx={{ minHeight: '100vh', display: 'flex', flexDirection: 'column' }}>
      <RuleReference />
    </Box>
  );
};

export default Content;
