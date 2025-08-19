# OpenWatch Design System

## 🎨 Core Design Philosophy

### Zero-Friction Principles
1. **Visual Hierarchy**: Important information stands out immediately
2. **Actionable Design**: Every element leads to a clear action
3. **Contextual Information**: Show data with next steps
4. **Consistent Patterns**: Same interactions work the same way everywhere
5. **Progressive Disclosure**: Show complexity only when needed

### Design Tokens

#### Colors
- **Primary**: Security Blue (#1976d2)
- **Success**: Compliance Green (#4caf50) 
- **Warning**: Attention Orange (#ff9800)
- **Error**: Critical Red (#f44336)
- **Info**: System Blue (#2196f3)

#### Severity Colors
- **Critical**: #f44336 (Red)
- **High**: #ff5722 (Deep Orange)
- **Medium**: #ff9800 (Orange) 
- **Low**: #ffc107 (Amber)
- **Info**: #2196f3 (Blue)

#### Status Colors
- **Online**: #4caf50 (Green)
- **Offline**: #f44336 (Red)
- **Maintenance**: #ff9800 (Orange)
- **Scanning**: #2196f3 (Blue)
- **Unknown**: #9e9e9e (Grey)

#### Typography Scale
- **Display**: 3.5rem (56px) - Page titles
- **H1**: 2.5rem (40px) - Section headers
- **H2**: 2rem (32px) - Subsection headers
- **H3**: 1.5rem (24px) - Card titles
- **H4**: 1.25rem (20px) - Small headers
- **Body**: 1rem (16px) - Main text
- **Caption**: 0.875rem (14px) - Meta information
- **Small**: 0.75rem (12px) - Labels, tags

#### Spacing Scale
- **xs**: 4px
- **sm**: 8px  
- **md**: 16px
- **lg**: 24px
- **xl**: 32px
- **2xl**: 48px
- **3xl**: 64px

#### Border Radius
- **sm**: 4px - Small elements
- **md**: 8px - Cards, buttons
- **lg**: 12px - Large cards
- **xl**: 16px - Modals
- **full**: 50% - Avatars, badges

#### Shadows
- **sm**: Subtle elevation
- **md**: Card elevation  
- **lg**: Modal elevation
- **xl**: Major elevation

### Component Patterns

#### 1. Status Indicators
- **Dot indicators** for quick status
- **Icon + text** for detailed status
- **Progress rings** for percentages
- **Trend arrows** for directional changes

#### 2. Action Patterns
- **Primary button** for main actions
- **Icon buttons** for quick actions
- **Floating Action Button** for page-level actions
- **Context menus** for item-specific actions
- **Bulk action toolbar** for multi-select

#### 3. Data Display
- **Statistics cards** for key metrics
- **Progress bars** for resource usage
- **Pie charts** for composition data
- **Trend sparklines** for historical data
- **Data tables** for detailed listings

#### 4. Navigation Patterns
- **Breadcrumbs** for context
- **Tab navigation** for related content
- **Collapsible groups** for organization
- **Search + filter** for findability

#### 5. Feedback Patterns
- **Toast notifications** for actions
- **Loading skeletons** for data loading
- **Empty states** with clear CTAs
- **Error states** with recovery options

### Layout Patterns

#### Dashboard Layout
```
[Statistics Row]
[Action Toolbar]  
[Content Area with Groups/Filters]
[Floating Actions]
```

#### Detail View Layout
```
[Header with Actions]
[Key Metrics Row]
[Tabbed Content Area]
[Related Items]
```

#### List View Layout
```
[Statistics/Summary]
[Search/Filter Toolbar]
[Bulk Actions] (if items selected)
[Items Grid/List]
[Pagination]
```

#### Form Layout
```
[Progress Indicator] (if multi-step)
[Form Header]
[Form Sections]
[Action Buttons]
```

### Interactive States

#### Hover States
- **Cards**: Slight elevation + shadow
- **Buttons**: Background color change
- **Icons**: Color change + scale
- **List items**: Background highlight

#### Selected States
- **Cards**: Border + shadow
- **List items**: Background + checkmark
- **Buttons**: Pressed appearance

#### Loading States
- **Skeleton screens** for initial loads
- **Progress indicators** for actions
- **Disabled states** during processing

#### Error States
- **Field validation** with clear messages
- **Page errors** with recovery actions
- **Network errors** with retry options

### Accessibility Guidelines

#### Color Contrast
- **Text**: Minimum 4.5:1 ratio
- **Large text**: Minimum 3:1 ratio
- **Interactive elements**: Clear focus indicators

#### Keyboard Navigation
- **Tab order**: Logical flow
- **Focus indicators**: Visible outlines
- **Keyboard shortcuts**: Consistent patterns

#### Screen Reader Support
- **Semantic HTML**: Proper headings, labels
- **ARIA labels**: For complex interactions
- **Alt text**: Descriptive image alternatives

### Animation Guidelines

#### Timing
- **Micro-interactions**: 150-200ms
- **Transitions**: 300ms
- **Page transitions**: 400-500ms

#### Easing
- **ease-out**: For entering elements
- **ease-in**: For exiting elements  
- **ease-in-out**: For moving elements

#### Purpose
- **Provide feedback** for user actions
- **Show relationships** between elements
- **Guide attention** to important changes
- **Maintain context** during transitions