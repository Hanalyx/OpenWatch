# Enhanced Error Handling Components

This directory contains React components for structured error handling and user guidance, transforming generic failures into guided resolution workflows.

## Components

### ErrorClassificationDisplay

A comprehensive error display component that shows structured errors with actionable guidance, automated fixes, and retry options.

**Features:**
- Categorized error display (network, authentication, privilege, resource, dependency)
- Severity levels with appropriate icons and colors
- User-friendly guidance messages
- Automated fix options with safety warnings
- Technical details (collapsible)
- Retry capabilities
- Documentation links
- Accessibility features (ARIA labels, screen reader support)

**Usage:**
```typescript
import ErrorClassificationDisplay from './ErrorClassificationDisplay';

<ErrorClassificationDisplay
  error={classifiedError}
  onRetry={handleRetry}
  onApplyFix={handleApplyFix}
  showTechnicalDetails={true}
  compact={false}
/>
```

### PreFlightValidationDialog

A modal dialog that performs comprehensive validation before scan execution, showing real-time progress and detailed results.

**Features:**
- Step-by-step validation progress (network, auth, privileges, resources, dependencies)
- Real-time status updates with visual indicators
- Collapsible error and warning sections
- System information display
- Automated fix integration
- Retry validation capability

**Usage:**
```typescript
import PreFlightValidationDialog from './PreFlightValidationDialog';

<PreFlightValidationDialog
  open={showDialog}
  onClose={handleClose}
  onProceed={handleProceed}
  validationRequest={{
    host_id: 'uuid',
    content_id: 123,
    profile_id: 'profile'
  }}
  title="Pre-Scan Validation"
/>
```

## Services

### errorService

A comprehensive error classification and handling service that transforms generic errors into structured, actionable information.

**Key Methods:**
- `validateScanPrerequisites()` - Pre-flight validation
- `classifyGenericError()` - Transform generic errors
- `getUserFriendlyError()` - Extract user-friendly messages
- `canRetryError()` - Check if error is retryable
- `getAutomatedFixes()` - Get available fixes

## Error Categories

- **Network**: DNS, connectivity, timeouts, firewall issues
- **Authentication**: Invalid credentials, SSH keys, account lockouts
- **Privilege**: Sudo access, SELinux, file permissions
- **Resource**: Disk space, memory, system resources
- **Dependency**: Missing packages, version compatibility
- **Content**: SCAP file issues, profile validation
- **Execution**: Runtime errors, unexpected failures
- **Configuration**: Settings, environment issues

## Integration Points

### With Backend API
- `POST /api/scans/validate` - Pre-flight validation
- `POST /api/scans/{id}/recover` - Recovery mechanisms
- `POST /api/hosts/{id}/apply-fix` - Automated fixes

### With Existing Components
- NewScapScan.tsx - Enhanced with pre-flight validation
- ScapContent.tsx - Structured upload error handling
- All API calls via enhanced error service

## Accessibility Features

- ARIA labels and descriptions
- Color + icon combinations for color-blind users
- Keyboard navigation support
- Screen reader announcements for status changes
- Semantic HTML structure
- Focus management in dialogs

## Testing

Components include data-testid attributes for reliable testing:
- `error-classification` - Main error display
- `preflight-validation-dialog` - Validation modal
- `validation-error-{index}` - Individual errors
- `fix-button-{fixId}` - Automated fix buttons
- `apply-fix-confirm` - Fix confirmation

## Material-UI Integration

Built with Material-UI v5 components:
- Dialog, Alert, Chip, LinearProgress
- Icons from @mui/icons-material
- Theme-aware colors and spacing
- Responsive design patterns

## Best Practices

1. **Progressive Disclosure**: Show simple view first, details on demand
2. **Actionable Guidance**: Always provide next steps, not just error descriptions
3. **Safety First**: Mark automated fixes with safety indicators
4. **Retry Logic**: Implement intelligent retry with backoff
5. **Context Preservation**: Maintain user's workflow state during error recovery
6. **Performance**: Use React.memo and careful re-render optimization

Last updated: 2025-08-25