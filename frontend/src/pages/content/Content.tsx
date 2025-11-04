import React, { useState } from 'react';
import { Container, Typography, Box, Tabs, Tab, Paper, useTheme, alpha } from '@mui/material';
import {
  Folder as ContentIcon,
  AccountTree as RulesIcon,
  Computer as PlatformIcon,
  Upload as UploadIcon,
  Sync as SyncIcon,
  CloudSync as UploadSyncIcon,
} from '@mui/icons-material';
import ComplianceRulesContent from './ComplianceRulesContent';
import RulesExplorerSimplified from '../../components/rules/RulesExplorerSimplified';
import PlatformCapabilityView from '../../components/platform/PlatformCapabilityView';
import UploadSyncRules from './UploadSyncRules';

interface TabPanelProps {
  children?: React.ReactNode;
  index: number;
  value: number;
}

function TabPanel(props: TabPanelProps) {
  const { children, value, index, ...other } = props;

  return (
    <div
      role="tabpanel"
      hidden={value !== index}
      id={`content-tabpanel-${index}`}
      aria-labelledby={`content-tab-${index}`}
      style={{ display: value === index ? 'block' : 'none' }}
      {...other}
    >
      {value === index && <Box sx={{ width: '100%' }}>{children}</Box>}
    </div>
  );
}

function a11yProps(index: number) {
  return {
    id: `content-tab-${index}`,
    'aria-controls': `content-tabpanel-${index}`,
  };
}

const Content: React.FC = () => {
  const theme = useTheme();
  const [currentTab, setCurrentTab] = useState(0);

  const handleTabChange = (event: React.SyntheticEvent, newValue: number) => {
    setCurrentTab(newValue);
  };

  return (
    <Container
      maxWidth="xl"
      sx={{ minHeight: '100vh', display: 'flex', flexDirection: 'column', pb: 4 }}
    >
      {/* Header */}
      <Box sx={{ py: 3 }}>
        <Typography variant="h4" gutterBottom>
          Content Library
        </Typography>
        <Typography variant="body1" color="text.secondary">
          Browse compliance rules from database, explore security configurations, configure platform
          capabilities, and manage rule updates
        </Typography>
      </Box>

      {/* Tabs */}
      <Box sx={{ borderBottom: 1, borderColor: 'divider', mb: 2 }}>
        <Tabs
          value={currentTab}
          onChange={handleTabChange}
          aria-label="content library tabs"
          sx={{
            '& .MuiTab-root': {
              minHeight: 64,
              textTransform: 'none',
              fontSize: '1rem',
            },
          }}
        >
          <Tab
            icon={<ContentIcon />}
            iconPosition="start"
            label="Compliance Rules"
            {...a11yProps(0)}
          />
          <Tab icon={<RulesIcon />} iconPosition="start" label="Rules Explorer" {...a11yProps(1)} />
          <Tab
            icon={<PlatformIcon />}
            iconPosition="start"
            label="Platform Capabilities"
            {...a11yProps(2)}
          />
          <Tab
            icon={<UploadSyncIcon />}
            iconPosition="start"
            label="Upload & Synchronize Rules"
            {...a11yProps(3)}
          />
        </Tabs>
      </Box>

      {/* Tab Content */}
      <Box sx={{ flex: 1, overflow: 'visible' }}>
        {/* Compliance Rules Tab */}
        <TabPanel value={currentTab} index={0}>
          <ComplianceRulesContent />
        </TabPanel>

        {/* Rules Explorer Tab */}
        <TabPanel value={currentTab} index={1}>
          <RulesExplorerSimplified />
        </TabPanel>

        {/* Platform Capabilities Tab */}
        <TabPanel value={currentTab} index={2}>
          <PlatformCapabilityView
            onRuleFilterChange={(platform, capabilities) => {
              // Switch to Rules Explorer tab and apply platform/capability filters
              setCurrentTab(1);
              // In a real implementation, this would trigger rule filtering
              console.log('Filter rules by platform:', platform, 'capabilities:', capabilities);
            }}
          />
        </TabPanel>

        {/* Upload & Synchronize Rules Tab */}
        <TabPanel value={currentTab} index={3}>
          <UploadSyncRules />
        </TabPanel>
      </Box>
    </Container>
  );
};

export default Content;
