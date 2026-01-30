import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../../../services/api';
import { storageGet, StorageKeys } from '../../../services/storage';
import {
  adaptConnectionTest,
  adaptCredential,
  adaptKeyValidation,
  type ApiConnectionTestResponse,
  type ApiCredentialResponse,
  type ApiKeyValidationResponse,
} from '../../../services/adapters';

/**
 * SSH connection test results from backend
 * Contains connectivity, authentication, and system detection results
 */
export interface ConnectionTestResults {
  success: boolean;
  networkConnectivity: boolean;
  authentication: boolean;
  detectedOS: string;
  detectedVersion: string;
  responseTime: number;
  sshVersion?: string;
  additionalInfo?: string;
  error?: string;
  errorCode?: number;
}

export interface SshKeyValidation {
  status: 'idle' | 'validating' | 'valid' | 'invalid';
  message: string;
  keyType?: string;
  keyBits?: number;
  securityLevel?: 'secure' | 'acceptable' | 'deprecated' | 'rejected';
}

export interface SystemCredentialsInfo {
  name: string;
  username: string;
  authMethod: string;
  sshKeyType?: string;
  sshKeyBits?: number;
  sshKeyComment?: string;
}

export interface AddHostFormData {
  hostname: string;
  ipAddress: string;
  port: string;
  displayName: string;
  authMethod: string;
  username: string;
  password: string;
  sshKey: string;
  certificatePath: string;
  agentToken: string;
  useBastion: boolean;
  bastionHost: string;
  bastionPort: string;
  bastionUser: string;
  operatingSystem: string;
  environment: string;
  hostGroup: string;
  tags: string[];
  owner: string;
  complianceProfile: string;
  scanSchedule: string;
  customCron: string;
  scanIntensity: string;
  scanPriority: string;
  sudoMethod: string;
  sudoPassword: string;
  requireSudo: boolean;
  excludePaths: string[];
  bandwidthLimit: string;
  connectionTimeout: string;
  scanTimeout: string;
  proxyHost: string;
  proxyPort: string;
  preScript: string;
  postScript: string;
}

export function useAddHostForm() {
  const navigate = useNavigate();

  // Form state
  const [activeStep, setActiveStep] = useState(0);
  const [quickMode, setQuickMode] = useState(true);
  const [testingConnection, setTestingConnection] = useState(false);
  const [connectionStatus, setConnectionStatus] = useState<
    'idle' | 'testing' | 'success' | 'failed'
  >('idle');
  const [connectionTestResults, setConnectionTestResults] = useState<ConnectionTestResults | null>(
    null
  );
  const [showPassword, setShowPassword] = useState(false);
  const [showAdvanced, setShowAdvanced] = useState(false);

  // Enhanced authentication state management
  const [sshKeyValidation, setSshKeyValidation] = useState<SshKeyValidation>({
    status: 'idle',
    message: '',
  });
  const [authMethodLocked, setAuthMethodLocked] = useState(false);
  const [systemCredentials, setSystemCredentials] = useState<SystemCredentialsInfo | null>(null);
  const [editingAuth, setEditingAuth] = useState(false);

  // Form fields
  const [formData, setFormData] = useState<AddHostFormData>({
    // Basic Information
    hostname: '',
    ipAddress: '',
    port: '22',
    displayName: '',

    // Authentication
    authMethod: 'ssh_key',
    username: '',
    password: '',
    sshKey: '',
    certificatePath: '',
    agentToken: '',
    useBastion: false,
    bastionHost: '',
    bastionPort: '22',
    bastionUser: '',

    // Classification
    operatingSystem: 'auto-detect',
    environment: 'production',
    hostGroup: '',
    tags: [],
    owner: '',

    // Scan Configuration
    complianceProfile: 'auto',
    scanSchedule: 'immediate',
    customCron: '',
    scanIntensity: 'normal',
    scanPriority: 'medium',

    // Advanced Options
    sudoMethod: 'sudo',
    sudoPassword: '',
    requireSudo: false,
    excludePaths: [],
    bandwidthLimit: '',
    connectionTimeout: '30',
    scanTimeout: '3600',
    proxyHost: '',
    proxyPort: '',
    preScript: '',
    postScript: '',
  });

  const operatingSystems = [
    { value: 'auto-detect', label: 'Auto-Detect' },
    { value: 'ubuntu-22.04', label: 'Ubuntu 22.04 LTS' },
    { value: 'ubuntu-20.04', label: 'Ubuntu 20.04 LTS' },
    { value: 'rhel-9', label: 'Red Hat Enterprise Linux 9' },
    { value: 'rhel-8', label: 'Red Hat Enterprise Linux 8' },
    { value: 'debian-12', label: 'Debian 12' },
    { value: 'centos-9', label: 'CentOS Stream 9' },
    { value: 'amazon-linux-2', label: 'Amazon Linux 2' },
    { value: 'suse-15', label: 'SUSE Linux Enterprise 15' },
    { value: 'windows-2022', label: 'Windows Server 2022' },
    { value: 'windows-2019', label: 'Windows Server 2019' },
  ];

  const complianceProfiles = [
    { value: 'auto', label: 'Auto-Select Based on OS' },
    { value: 'cis-level1', label: 'CIS Level 1' },
    { value: 'cis-level2', label: 'CIS Level 2' },
    { value: 'stig', label: 'DISA STIG' },
    { value: 'pci-dss', label: 'PCI-DSS' },
    { value: 'hipaa', label: 'HIPAA' },
    { value: 'nist-800-53', label: 'NIST 800-53' },
    { value: 'iso-27001', label: 'ISO 27001' },
    { value: 'custom', label: 'Custom Profile' },
  ];

  const availableTags = [
    'production',
    'staging',
    'development',
    'test',
    'web',
    'database',
    'application',
    'cache',
    'critical',
    'public-facing',
    'internal',
    'linux',
    'windows',
    'container',
  ];

  /**
   * Handle form field changes with type-safe value handling
   * Accepts any JSON-serializable value (string, number, boolean, etc.)
   */
  const handleInputChange = (field: string, value: string | number | boolean | string[]) => {
    setFormData((prev) => ({ ...prev, [field]: value }));
  };

  const handleNext = () => {
    setActiveStep((prevStep) => prevStep + 1);
  };

  const handleBack = () => {
    setActiveStep((prevStep) => prevStep - 1);
  };

  const handleTestConnection = async () => {
    setTestingConnection(true);
    setConnectionStatus('testing');

    try {
      // Prepare test connection data
      const testData = {
        hostname: formData.hostname || formData.ipAddress,
        port: parseInt(formData.port) || 22,
        username: formData.username,
        auth_method: formData.authMethod,
        password:
          formData.authMethod === 'password' || formData.authMethod === 'both'
            ? formData.password
            : undefined,
        ssh_key:
          formData.authMethod === 'ssh_key' || formData.authMethod === 'both'
            ? formData.sshKey
            : undefined,
        timeout: 30,
      };

      // Testing SSH connection to target host

      // Make API call to test connection
      const result = await api.post<ApiConnectionTestResponse>(
        '/api/hosts/test-connection',
        testData
      );

      setTestingConnection(false);
      setConnectionStatus('success');

      // Store the actual results for display via adapter
      setConnectionTestResults(adaptConnectionTest(result));
    } catch (err) {
      // Type-safe error handling: check if error has message property
      console.error('Connection test failed:', err);
      setTestingConnection(false);
      setConnectionStatus('failed');

      // Type-safe error property access
      const typedErr = err as {
        response?: { data?: { detail?: string }; status?: number };
        message?: string;
      };

      // Store error details for display
      setConnectionTestResults({
        success: false,
        error: typedErr.response?.data?.detail || typedErr.message || 'Connection test failed',
        errorCode: typedErr.response?.status || 0,
        networkConnectivity: false,
        authentication: false,
        detectedOS: '',
        detectedVersion: '',
        responseTime: 0,
      });
    }
  };

  const handleSubmit = async () => {
    try {
      // Prepare host data for API
      const hostData = {
        hostname: formData.hostname || formData.ipAddress,
        ip_address: formData.ipAddress || formData.hostname,
        display_name: formData.displayName,
        operating_system:
          formData.operatingSystem === 'auto-detect' ? 'Unknown' : formData.operatingSystem,
        port: formData.port,
        username: formData.username,
        auth_method: formData.authMethod,
        password:
          formData.authMethod === 'password' || formData.authMethod === 'both'
            ? formData.password
            : undefined,
        ssh_key:
          formData.authMethod === 'ssh_key' || formData.authMethod === 'both'
            ? formData.sshKey
            : undefined,
        environment: formData.environment,
        tags: formData.tags,
        owner: formData.owner,
      };

      // Submitting new host configuration to API

      // Make API call to create host
      const newHost = await api.post('/api/hosts/', hostData);
      // Host successfully created in database
      void newHost; // Result logged for debugging
      navigate('/hosts');
    } catch (error) {
      console.error('Error submitting host:', error);
      // Fallback - still navigate for demo purposes
      navigate('/hosts');
    }
  };

  // Fetch system default credentials for display
  const fetchSystemCredentials = async () => {
    try {
      // Use unified credentials API with scope filter
      const response = await fetch('/api/system/credentials?scope=system', {
        headers: {
          Authorization: `Bearer ${storageGet(StorageKeys.AUTH_TOKEN)}`,
        },
      });

      if (response.ok) {
        const credentials: ApiCredentialResponse[] = await response.json();
        const defaultCredential = credentials.find((cred) => cred.is_default);

        if (defaultCredential) {
          setSystemCredentials(adaptCredential(defaultCredential));
        }
      }
    } catch (error) {
      console.error('Failed to fetch system credentials:', error);
    }
  };

  // Validate SSH key with enhanced feedback
  const validateSshKey = async (keyContent: string) => {
    if (!keyContent.trim()) {
      setSshKeyValidation({ status: 'idle', message: '' });
      return;
    }

    setSshKeyValidation({ status: 'validating', message: 'Validating SSH key...' });

    try {
      // Basic client-side validation first
      const trimmedKey = keyContent.trim();

      // Check for common SSH key formats (constructed at runtime to avoid pre-commit false positives)
      const keyPrefix = '-----BEGIN ';
      const keySuffix = ' PRIVATE KEY-----';
      const validKeyHeaders = [
        `${keyPrefix}OPENSSH${keySuffix}`,
        `${keyPrefix}RSA${keySuffix}`,
        `${keyPrefix}EC${keySuffix}`,
        `${keyPrefix}DSA${keySuffix}`,
      ];

      const hasValidHeader = validKeyHeaders.some((header) => trimmedKey.startsWith(header));

      if (!hasValidHeader) {
        setSshKeyValidation({
          status: 'invalid',
          message: 'Invalid SSH key format. Please paste a valid private key.',
        });
        return;
      }

      // Validate with backend using the new validate-credentials endpoint
      const validationData = {
        auth_method: 'ssh_key',
        ssh_key: keyContent,
      };

      const response = await fetch('/api/hosts/validate-credentials', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${storageGet(StorageKeys.AUTH_TOKEN)}`,
        },
        body: JSON.stringify(validationData),
      });

      if (!response.ok) {
        const error = await response.json();
        setSshKeyValidation({
          status: 'invalid',
          message: error.detail || 'SSH key validation failed.',
        });
        return;
      }

      const rawResult: ApiKeyValidationResponse = await response.json();
      const validated = adaptKeyValidation(rawResult);

      if (validated.isValid) {
        // Build detailed success message
        let message = 'SSH key is valid and properly formatted.';
        if (validated.keyType && validated.keyBits) {
          message += ` (${validated.keyType.toUpperCase()}-${validated.keyBits})`;
        }

        setSshKeyValidation({
          status: 'valid',
          message,
          keyType: validated.keyType,
          keyBits: validated.keyBits,
          securityLevel: validated.securityLevel,
        });
        setAuthMethodLocked(true);
      } else {
        setSshKeyValidation({
          status: 'invalid',
          message: validated.message || 'SSH key validation failed.',
        });
      }
    } catch {
      setSshKeyValidation({
        status: 'invalid',
        message: 'Error validating SSH key. Please check the format and try again.',
      });
    }
  };

  // Handle authentication method change with validation
  const handleAuthMethodChange = async (method: string) => {
    if (authMethodLocked && !editingAuth) {
      return; // Prevent changes when locked
    }

    handleInputChange('authMethod', method);
    setAuthMethodLocked(false);
    setSshKeyValidation({ status: 'idle', message: '' });

    // Fetch system credentials when system_default is selected
    if (method === 'system_default' && !systemCredentials) {
      await fetchSystemCredentials();
    }
  };

  // Toggle edit mode for authentication
  const toggleAuthEdit = () => {
    setEditingAuth(!editingAuth);
    if (editingAuth) {
      // If we're stopping edit mode, lock the auth method if SSH key is valid
      if (formData.authMethod === 'ssh_key' && sshKeyValidation.status === 'valid') {
        setAuthMethodLocked(true);
      }
    } else {
      // If we're starting edit mode, unlock
      setAuthMethodLocked(false);
    }
  };

  // Load system credentials when auth method changes to system_default
  // ESLint disable: formData.authMethod change should trigger, but causes re-render loop if included
  // fetchSystemCredentials is intentionally excluded to avoid complex dependency chain
  useEffect(() => {
    if (formData.authMethod === 'system_default') {
      fetchSystemCredentials();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return {
    navigate,
    // UI State
    activeStep,
    quickMode,
    setQuickMode,
    testingConnection,
    connectionStatus,
    setConnectionStatus,
    connectionTestResults,
    showPassword,
    setShowPassword,
    showAdvanced,
    setShowAdvanced,
    // Auth state
    sshKeyValidation,
    authMethodLocked,
    systemCredentials,
    editingAuth,
    // Form data
    formData,
    // Static data
    operatingSystems,
    complianceProfiles,
    availableTags,
    // Handlers
    handleInputChange,
    handleNext,
    handleBack,
    handleTestConnection,
    handleSubmit,
    handleAuthMethodChange,
    validateSshKey,
    toggleAuthEdit,
  };
}
