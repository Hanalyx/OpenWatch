import type { Meta, StoryObj } from '@storybook/react';
import { StatCard } from './index';
import { Computer, Security, Assessment, TrendingUp, TrendingDown } from '@mui/icons-material';

/**
 * StatCard displays key metrics and statistics in a visually appealing card format.
 * It supports icons, trend indicators, and responsive design patterns.
 */
const meta: Meta<typeof StatCard> = {
  title: 'Design System/Components/StatCard',
  component: StatCard,
  parameters: {
    layout: 'padded',
    docs: {
      description: {
        component: `
The StatCard component is used throughout OpenWatch to display key metrics and statistics.
It provides a consistent visual language for presenting numerical data with contextual information.

### Features
- **Responsive Design**: Adapts to different screen sizes
- **Icon Support**: Customizable icons for visual context
- **Trend Indicators**: Shows positive/negative trends with appropriate colors
- **Accessibility**: WCAG 2.1 AA compliant with proper ARIA labels
- **Material Design 3**: Follows M3 design principles
        `,
      },
    },
  },
  tags: ['autodocs'],
  argTypes: {
    title: {
      control: 'text',
      description: 'The title/label for the statistic',
    },
    value: {
      control: 'text',
      description: 'The main value to display',
    },
    subtitle: {
      control: 'text',
      description: 'Additional descriptive text',
    },
    icon: {
      control: false,
      description: 'Icon component to display',
    },
    trend: {
      control: { type: 'select' },
      options: ['up', 'down', 'neutral'],
      description: 'Trend direction indicator',
    },
    trendValue: {
      control: 'text',
      description: 'Trend percentage or value',
    },
    color: {
      control: { type: 'select' },
      options: ['primary', 'secondary', 'success', 'warning', 'error', 'info'],
      description: 'Color theme for the card',
    },
    loading: {
      control: 'boolean',
      description: 'Show loading skeleton',
    },
    onClick: {
      action: 'clicked',
      description: 'Click handler for interactive cards',
    },
  },
};

export default meta;
type Story = StoryObj<typeof meta>;

/**
 * Default StatCard with basic information
 */
export const Default: Story = {
  args: {
    title: 'Total Hosts',
    value: '124',
    subtitle: 'Monitored systems',
    icon: <Computer />,
  },
};

/**
 * StatCard with positive trend indicator
 */
export const WithPositiveTrend: Story = {
  args: {
    title: 'Compliance Score',
    value: '94%',
    subtitle: 'SCAP compliance rate',
    icon: <Security />,
    trend: 'up',
    trendValue: '+2.3%',
    color: 'success',
  },
};

/**
 * StatCard with negative trend indicator
 */
export const WithNegativeTrend: Story = {
  args: {
    title: 'Failed Scans',
    value: '8',
    subtitle: 'In the last 24 hours',
    icon: <Assessment />,
    trend: 'down',
    trendValue: '-15%',
    color: 'error',
  },
};

/**
 * Loading state with skeleton animation
 */
export const Loading: Story = {
  args: {
    title: 'Loading...',
    value: '---',
    subtitle: 'Please wait',
    icon: <Computer />,
    loading: true,
  },
};

/**
 * Interactive StatCard that responds to clicks
 */
export const Interactive: Story = {
  args: {
    title: 'Active Scans',
    value: '12',
    subtitle: 'Currently running',
    icon: <Assessment />,
    color: 'info',
    onClick: () => console.log('StatCard clicked!'),
  },
  parameters: {
    docs: {
      description: {
        story: 'This StatCard is interactive and will trigger an action when clicked.',
      },
    },
  },
};

/**
 * Different color variations
 */
export const ColorVariations: Story = {
  render: () => (
    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))', gap: '1rem' }}>
      <StatCard
        title="Primary"
        value="100"
        subtitle="Primary color theme"
        icon={<Computer />}
        color="primary"
      />
      <StatCard
        title="Secondary"
        value="85"
        subtitle="Secondary color theme"
        icon={<Security />}
        color="secondary"
      />
      <StatCard
        title="Success"
        value="98%"
        subtitle="Success color theme"
        icon={<TrendingUp />}
        color="success"
        trend="up"
        trendValue="+5%"
      />
      <StatCard
        title="Warning"
        value="23"
        subtitle="Warning color theme"
        icon={<Assessment />}
        color="warning"
      />
      <StatCard
        title="Error"
        value="5"
        subtitle="Error color theme"
        icon={<TrendingDown />}
        color="error"
        trend="down"
        trendValue="-12%"
      />
      <StatCard
        title="Info"
        value="42"
        subtitle="Info color theme"
        icon={<Computer />}
        color="info"
      />
    </div>
  ),
  parameters: {
    docs: {
      description: {
        story: 'StatCard supports different color themes to match various data types and semantic meanings.',
      },
    },
  },
};

/**
 * Responsive grid layout example
 */
export const ResponsiveGrid: Story = {
  render: () => (
    <div style={{ 
      display: 'grid', 
      gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', 
      gap: '1rem',
      maxWidth: '800px' 
    }}>
      <StatCard
        title="Hosts"
        value="124"
        subtitle="Total monitored"
        icon={<Computer />}
        color="primary"
      />
      <StatCard
        title="Compliance"
        value="94%"
        subtitle="Overall score"
        icon={<Security />}
        color="success"
        trend="up"
        trendValue="+2%"
      />
      <StatCard
        title="Scans"
        value="1,847"
        subtitle="This month"
        icon={<Assessment />}
        color="info"
        trend="up"
        trendValue="+18%"
      />
      <StatCard
        title="Issues"
        value="23"
        subtitle="Need attention"
        icon={<Assessment />}
        color="warning"
        trend="down"
        trendValue="-8%"
      />
    </div>
  ),
  parameters: {
    docs: {
      description: {
        story: 'StatCards work well in responsive grid layouts and automatically adapt to different screen sizes.',
      },
    },
    viewport: {
      defaultViewport: 'desktop',
    },
  },
};

/**
 * Accessibility example with proper ARIA labels
 */
export const AccessibilityExample: Story = {
  args: {
    title: 'Security Score',
    value: '87%',
    subtitle: 'Overall security compliance',
    icon: <Security />,
    trend: 'up',
    trendValue: '+3.2%',
    color: 'success',
  },
  parameters: {
    docs: {
      description: {
        story: `
This StatCard includes proper accessibility features:
- ARIA labels for screen readers
- High contrast colors (WCAG 2.1 AA compliant)
- Keyboard navigation support
- Focus indicators
        `,
      },
    },
    a11y: {
      config: {
        rules: [
          {
            id: 'color-contrast',
            enabled: true,
          },
          {
            id: 'keyboard-navigation',
            enabled: true,
          },
        ],
      },
    },
  },
};