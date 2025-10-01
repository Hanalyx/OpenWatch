// MongoDB initialization script for framework control definitions
// This script populates the framework_control_definitions collection with standardized control data

print("Starting framework control definitions initialization...");

// Create the framework_control_definitions collection with indexes
db.createCollection("framework_control_definitions");

// Create comprehensive indexes for performance
print("Creating indexes for framework_control_definitions...");

// Primary query indexes
db.framework_control_definitions.createIndex({ "framework_id": 1 });
db.framework_control_definitions.createIndex({ "control_id": 1 });
db.framework_control_definitions.createIndex({ "framework_id": 1, "control_id": 1 }, { unique: true });

// Search and filtering indexes
db.framework_control_definitions.createIndex({ "family": 1 });
db.framework_control_definitions.createIndex({ "priority": 1 });
db.framework_control_definitions.createIndex({ "severity": 1 });

// Cross-reference mapping indexes
db.framework_control_definitions.createIndex({ "external_references.nist": 1 });
db.framework_control_definitions.createIndex({ "external_references.cis": 1 });
db.framework_control_definitions.createIndex({ "external_references.srg": 1 });
db.framework_control_definitions.createIndex({ "external_references.cci": 1 });

// Text search index for descriptions and guidance
db.framework_control_definitions.createIndex({
  "title": "text",
  "description": "text",
  "supplemental_guidance": "text"
});

// Compound indexes for complex queries
db.framework_control_definitions.createIndex({ "framework_id": 1, "family": 1 });
db.framework_control_definitions.createIndex({ "framework_id": 1, "priority": 1 });

// Load NIST 800-53 R5 Controls
print("Loading NIST 800-53 R5 Controls...");
load("/docker-entrypoint-initdb.d/framework_definitions/nist_800_53_r5.json");

// Insert NIST Controls into framework_control_definitions
db.framework_control_definitions.insertMany(
  nist_framework.controls.map(control => ({
    framework_id: nist_framework.framework_info.id,
    control_id: control.control_id,
    title: control.title,
    family: control.family,
    priority: control.priority,
    description: control.description,
    supplemental_guidance: control.supplemental_guidance,
    related_controls: control.related_controls || [],
    external_references: control.external_references || {},
    framework_version: nist_framework.framework_info.version,
    framework_organization: nist_framework.framework_info.organization,
    created_at: new Date(),
    updated_at: new Date()
  }))
);

// Load CIS Controls v8
print("Loading CIS Controls v8...");
load("/docker-entrypoint-initdb.d/framework_definitions/cis_v8.json");

// Insert CIS Controls into framework_control_definitions
db.framework_control_definitions.insertMany(
  cis_framework.controls.map(control => ({
    framework_id: cis_framework.framework_info.id,
    control_id: control.control_id,
    title: control.title,
    family: control.asset_type,
    priority: control.implementation_groups ? control.implementation_groups.join(", ") : null,
    description: control.description,
    supplemental_guidance: null,
    related_controls: [],
    external_references: control.external_references || {},
    framework_version: cis_framework.framework_info.version,
    framework_organization: cis_framework.framework_info.organization,
    created_at: new Date(),
    updated_at: new Date(),
    // CIS-specific fields
    asset_type: control.asset_type,
    implementation_groups: control.implementation_groups || [],
    safeguards: control.safeguards || []
  }))
);

// Load SRG OS Controls
print("Loading SRG OS Controls...");
load("/docker-entrypoint-initdb.d/framework_definitions/srg_os.json");

// Insert SRG Controls into framework_control_definitions
db.framework_control_definitions.insertMany(
  srg_framework.controls.map(control => ({
    framework_id: srg_framework.framework_info.id,
    control_id: control.control_id,
    title: control.title,
    family: "Security Requirements",
    priority: control.severity,
    description: control.description,
    supplemental_guidance: control.vulnerability_discussion,
    related_controls: control.related_controls || [],
    external_references: {
      nist: control.nist_controls ? control.nist_controls.join(", ") : null,
      cci: control.cci ? control.cci.join(", ") : null
    },
    framework_version: srg_framework.framework_info.version,
    framework_organization: srg_framework.framework_info.organization,
    created_at: new Date(),
    updated_at: new Date(),
    // SRG-specific fields
    severity: control.severity,
    check_text: control.check_text,
    fix_text: control.fix_text,
    cci: control.cci || [],
    nist_controls: control.nist_controls || [],
    requirement_source: control.requirement_source
  }))
);

// Load STIG RHEL 9 Controls
print("Loading STIG RHEL 9 Controls...");
load("/docker-entrypoint-initdb.d/framework_definitions/stig_rhel9.json");

// Insert STIG Controls into framework_control_definitions
db.framework_control_definitions.insertMany(
  stig_framework.controls.map(control => ({
    framework_id: stig_framework.framework_info.id,
    control_id: control.control_id,
    title: control.title,
    family: "STIG Implementation",
    priority: control.severity,
    description: control.description,
    supplemental_guidance: control.vulnerability_discussion,
    related_controls: control.related_controls || [],
    external_references: {
      srg: control.srg_requirement,
      nist: control.nist_controls ? control.nist_controls.join(", ") : null,
      cci: control.cci ? control.cci.join(", ") : null
    },
    framework_version: stig_framework.framework_info.version,
    framework_organization: stig_framework.framework_info.organization,
    created_at: new Date(),
    updated_at: new Date(),
    // STIG-specific fields
    severity: control.severity,
    check_text: control.check_text,
    fix_text: control.fix_text,
    cci: control.cci || [],
    nist_controls: control.nist_controls || [],
    srg_requirement: control.srg_requirement,
    implementation_details: control.implementation_details,
    target_platform: stig_framework.framework_info.target_platform
  }))
);

// Load ISO 27001:2022 Controls
print("Loading ISO 27001:2022 Controls...");
load("/docker-entrypoint-initdb.d/framework_definitions/iso_27001_2022.json");

// Insert ISO Controls into framework_control_definitions
db.framework_control_definitions.insertMany(
  iso_framework.controls.map(control => ({
    framework_id: iso_framework.framework_info.id,
    control_id: control.control_id,
    title: control.title,
    family: control.category,
    priority: control.implementation_level,
    description: control.description,
    supplemental_guidance: control.implementation_guidance,
    related_controls: control.related_controls || [],
    external_references: control.external_references || {},
    framework_version: iso_framework.framework_info.version,
    framework_organization: iso_framework.framework_info.organization,
    created_at: new Date(),
    updated_at: new Date(),
    // ISO-specific fields
    category: control.category,
    implementation_level: control.implementation_level,
    implementation_guidance: control.implementation_guidance,
    objective: control.objective,
    compliance_evidence: control.compliance_evidence || []
  }))
);

// Load PCI-DSS v4.0 Controls
print("Loading PCI-DSS v4.0 Controls...");
load("/docker-entrypoint-initdb.d/framework_definitions/pci_dss_v4.json");

// Insert PCI-DSS Controls into framework_control_definitions
db.framework_control_definitions.insertMany(
  pci_framework.controls.map(control => ({
    framework_id: pci_framework.framework_info.id,
    control_id: control.control_id,
    title: control.title,
    family: control.category,
    priority: control.validation_level,
    description: control.description,
    supplemental_guidance: control.guidance,
    related_controls: control.related_controls || [],
    external_references: control.external_references || {},
    framework_version: pci_framework.framework_info.version,
    framework_organization: pci_framework.framework_info.organization,
    created_at: new Date(),
    updated_at: new Date(),
    // PCI-DSS-specific fields
    requirement: control.requirement,
    requirement_title: control.requirement_title,
    category: control.category,
    validation_level: control.validation_level,
    testing_procedures: control.testing_procedures || [],
    guidance: control.guidance,
    customization: control.customization,
    compliance_evidence: control.compliance_evidence || []
  }))
);

print("Framework control definitions loaded successfully!");
print("Total NIST controls:", db.framework_control_definitions.countDocuments({framework_id: "nist_800_53_r5"}));
print("Total CIS controls:", db.framework_control_definitions.countDocuments({framework_id: "cis_v8"}));
print("Total SRG controls:", db.framework_control_definitions.countDocuments({framework_id: "srg_os"}));
print("Total STIG RHEL 9 controls:", db.framework_control_definitions.countDocuments({framework_id: "stig_rhel9"}));
print("Total ISO 27001 controls:", db.framework_control_definitions.countDocuments({framework_id: "iso_27001_2022"}));
print("Total PCI-DSS controls:", db.framework_control_definitions.countDocuments({framework_id: "pci_dss_v4"}));

// Create framework_info collection for metadata
print("Creating framework_info collection...");
db.createCollection("framework_info");

// Insert framework metadata
db.framework_info.insertMany([
  {
    framework_id: "nist_800_53_r5",
    ...nist_framework.framework_info,
    created_at: new Date(),
    updated_at: new Date()
  },
  {
    framework_id: "cis_v8",
    ...cis_framework.framework_info,
    created_at: new Date(),
    updated_at: new Date()
  },
  {
    framework_id: "srg_os",
    ...srg_framework.framework_info,
    created_at: new Date(),
    updated_at: new Date()
  },
  {
    framework_id: "stig_rhel9",
    ...stig_framework.framework_info,
    created_at: new Date(),
    updated_at: new Date()
  },
  {
    framework_id: "iso_27001_2022",
    ...iso_framework.framework_info,
    created_at: new Date(),
    updated_at: new Date()
  },
  {
    framework_id: "pci_dss_v4",
    ...pci_framework.framework_info,
    created_at: new Date(),
    updated_at: new Date()
  }
]);

print("Framework initialization completed successfully!");