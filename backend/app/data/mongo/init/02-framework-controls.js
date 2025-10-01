// MongoDB initialization script for framework control definitions
// This script populates the framework_control_definitions collection

// Switch to the OpenWatch rules database
db = db.getSiblingDB('openwatch_rules');

print('Initializing framework control definitions...');

// Create framework_control_definitions collection if it doesn't exist
db.createCollection('framework_control_definitions');

// Create indexes for optimal query performance
print('Creating indexes for framework_control_definitions...');

db.framework_control_definitions.createIndex(
    { "framework_id": 1, "control_id": 1 }, 
    { "unique": true, "name": "idx_framework_control_unique" }
);

db.framework_control_definitions.createIndex(
    { "framework_id": 1 }, 
    { "name": "idx_framework_id" }
);

db.framework_control_definitions.createIndex(
    { "control_id": 1 }, 
    { "name": "idx_control_id" }
);

db.framework_control_definitions.createIndex(
    { "family": 1 }, 
    { "name": "idx_family" }
);

db.framework_control_definitions.createIndex(
    { "priority": 1 }, 
    { "name": "idx_priority" }
);

db.framework_control_definitions.createIndex(
    { "title": "text", "description": "text" }, 
    { "name": "idx_text_search" }
);

// Load NIST 800-53 R5 control definitions
print('Loading NIST 800-53 R5 control definitions...');

const nistControls = [
    {
        framework_id: "nist_800_53_r5",
        control_id: "AC-1",
        title: "Policy and Procedures",
        description: "Develop, document, and disseminate access control policy and procedures.",
        family: "Access Control",
        priority: "P1",
        supplemental_guidance: "Access control policy and procedures for the controls in the AC family implemented within systems and organizations.",
        related_controls: ["PM-9", "PS-8", "SI-12"],
        external_references: {
            "cis": "5.1",
            "iso": "A.9.1.1"
        }
    },
    {
        framework_id: "nist_800_53_r5",
        control_id: "AC-2",
        title: "Account Management",
        description: "Manage information system accounts including establishing, activating, modifying, reviewing, disabling, and removing accounts.",
        family: "Access Control",
        priority: "P1",
        supplemental_guidance: "Account management applies to all account types including individual, shared, group, system, guest, anonymous, emergency, developer, temporary, and service accounts.",
        related_controls: ["AC-3", "AC-5", "AC-6", "AC-10", "AC-17", "AC-19", "AC-20", "AU-9", "IA-2", "IA-4", "IA-5", "IA-8"],
        external_references: {
            "cis": "5.1",
            "iso": "A.9.2.1"
        }
    },
    {
        framework_id: "nist_800_53_r5",
        control_id: "AC-3",
        title: "Access Enforcement", 
        description: "Enforce approved authorizations for logical access to information and system resources.",
        family: "Access Control",
        priority: "P1",
        supplemental_guidance: "Access control policies control access between active entities or subjects and passive entities or objects.",
        related_controls: ["AC-2", "AC-4", "AC-5", "AC-6", "AC-16", "AC-17", "AC-18", "AC-19", "AC-20", "AC-21", "AC-22"],
        external_references: {
            "cis": "5.3",
            "iso": "A.9.1.2"
        }
    },
    {
        framework_id: "nist_800_53_r5",
        control_id: "IA-5",
        title: "Authenticator Management",
        description: "Manage system authenticators by verifying the identity of the individual, group, role, or device.",
        family: "Identification and Authentication",
        priority: "P1",
        supplemental_guidance: "Individual authenticators include passwords, tokens, biometrics, PKI certificates, and key cards.",
        related_controls: ["AC-2", "AC-3", "AC-6", "CM-6", "IA-2", "IA-4", "IA-8", "IA-12"],
        external_references: {
            "cis": "5.3.1",
            "iso": "A.9.4.3"
        }
    },
    {
        framework_id: "nist_800_53_r5",
        control_id: "IA-5(1)",
        title: "Password-Based Authentication",
        description: "For password-based authentication, maintain password policies and procedures.",
        family: "Identification and Authentication",
        priority: "P1",
        supplemental_guidance: "Password policies include password complexity, length, reuse, and lifetime restrictions.",
        related_controls: ["IA-5"],
        external_references: {
            "cis": "5.3.1",
            "iso": "A.9.4.3"
        }
    },
    {
        framework_id: "nist_800_53_r5",
        control_id: "IA-5(4)",
        title: "Automated Support for Password Strength Determination",
        description: "Employ automated tools to determine if password authenticators are sufficiently strong.",
        family: "Identification and Authentication",
        priority: "P2",
        supplemental_guidance: "Automated tools can check passwords against commonly used, expected, or compromised passwords.",
        related_controls: ["IA-5"],
        external_references: {
            "cis": "5.3.2"
        }
    },
    {
        framework_id: "nist_800_53_r5",
        control_id: "SC-13",
        title: "Cryptographic Protection",
        description: "Determine the cryptographic uses and implement required cryptographic protections using cryptographic mechanisms.",
        family: "System and Communications Protection",
        priority: "P1",
        supplemental_guidance: "Cryptographic mechanisms used by the system are employed in accordance with applicable laws, executive orders, directives, regulations, policies, standards, and guidelines.",
        related_controls: ["AC-2", "AC-3", "AC-7", "AC-17", "AC-18", "AU-9", "AU-10"],
        external_references: {
            "cis": "1.11",
            "iso": "A.10.1.1"
        }
    },
    {
        framework_id: "nist_800_53_r5",
        control_id: "AU-2",
        title: "Event Logging",
        description: "Identify the types of events that the system is capable of logging in support of the audit function.",
        family: "Audit and Accountability",
        priority: "P1",
        supplemental_guidance: "An event is an observable occurrence in a system. The types of events that require logging are those events that are significant and relevant to the security of systems and the privacy of individuals.",
        related_controls: ["AC-6", "AC-17", "AU-3", "AU-12", "CA-7"],
        external_references: {
            "cis": "8.2",
            "iso": "A.12.4.1"
        }
    },
    {
        framework_id: "nist_800_53_r5",
        control_id: "CM-6",
        title: "Configuration Settings",
        description: "Establish and document configuration settings for components employed within the system using security and privacy configuration checklists.",
        family: "Configuration Management",
        priority: "P1",
        supplemental_guidance: "Configuration settings are the parameters that can be changed in the hardware, software, or firmware that affect the security and privacy posture or functionality of the system.",
        related_controls: ["AC-3", "AC-19", "AU-2", "AU-6", "CA-9"],
        external_references: {
            "cis": "4.3.1",
            "iso": "A.12.6.1"
        }
    }
];

// Load CIS v8 control definitions
print('Loading CIS v8 control definitions...');

const cisControls = [
    {
        framework_id: "cis_v8",
        control_id: "1",
        title: "Inventory and Control of Enterprise Assets",
        description: "Actively manage (inventory, track, and correct) all enterprise assets connected to the infrastructure.",
        family: "Asset Management",
        priority: "IG1",
        supplemental_guidance: "Includes end-user devices, network devices, non-computing/IoT devices, and servers.",
        related_controls: ["1.1", "1.2", "1.3"],
        external_references: {
            "nist": "CM-8",
            "iso": "A.8.1.1"
        }
    },
    {
        framework_id: "cis_v8",
        control_id: "1.1",
        title: "Establish and Maintain Detailed Enterprise Asset Inventory",
        description: "Establish and maintain an accurate, detailed, and up-to-date inventory of all enterprise assets.",
        family: "Asset Management",
        priority: "IG1",
        supplemental_guidance: "Asset inventory should include end-user devices, network devices, non-computing/IoT devices, and servers.",
        related_controls: ["1"],
        external_references: {
            "nist": "CM-8",
            "iso": "A.8.1.1"
        }
    },
    {
        framework_id: "cis_v8",
        control_id: "5",
        title: "Account Management",
        description: "Use processes and tools to assign and manage authorization to credentials for user accounts.",
        family: "Access Control",
        priority: "IG1",
        supplemental_guidance: "Includes administrator accounts and service accounts to enterprise assets and software.",
        related_controls: ["5.1", "5.2", "5.3"],
        external_references: {
            "nist": "AC-2",
            "iso": "A.9.2.1"
        }
    },
    {
        framework_id: "cis_v8",
        control_id: "5.1",
        title: "Establish and Maintain an Inventory of Accounts",
        description: "Establish and maintain an inventory of all accounts managed in the enterprise.",
        family: "Access Control",
        priority: "IG1",
        supplemental_guidance: "Account inventory should be comprehensive and regularly updated.",
        related_controls: ["5"],
        external_references: {
            "nist": "AC-2",
            "iso": "A.9.2.1"
        }
    },
    {
        framework_id: "cis_v8",
        control_id: "5.3",
        title: "Disable Dormant Accounts",
        description: "Delete or disable any dormant accounts after a period of 45 days of inactivity.",
        family: "Access Control",
        priority: "IG1",
        supplemental_guidance: "Apply where supported by the system.",
        related_controls: ["5"],
        external_references: {
            "nist": "AC-2(3)",
            "iso": "A.9.2.5"
        }
    },
    {
        framework_id: "cis_v8",
        control_id: "5.3.1",
        title: "Enforce Password Complexity",
        description: "Enforce minimum password length of 14 characters and complexity requirements.",
        family: "Access Control",
        priority: "IG1",
        supplemental_guidance: "Password complexity should include multiple character types.",
        related_controls: ["5.3.2"],
        external_references: {
            "nist": "IA-5(1)",
            "iso": "A.9.4.3"
        }
    },
    {
        framework_id: "cis_v8",
        control_id: "5.3.2",
        title: "Disable Weak Cryptographic Functions",
        description: "Disable or remove any cryptographic functions that are not meeting organizational requirements.",
        family: "Cryptography",
        priority: "IG2",
        supplemental_guidance: "Includes weak hash functions like MD5 and SHA1.",
        related_controls: ["5.3.1"],
        external_references: {
            "nist": "SC-13",
            "iso": "A.10.1.1"
        }
    },
    {
        framework_id: "cis_v8",
        control_id: "4.3.1",
        title: "Securely Configure Network Infrastructure",
        description: "Securely configure network infrastructure to include secure administrative access controls.",
        family: "Configuration Management",
        priority: "IG2",
        supplemental_guidance: "Network infrastructure should follow security configuration standards.",
        related_controls: ["4.3"],
        external_references: {
            "nist": "CM-6",
            "iso": "A.12.6.1"
        }
    },
    {
        framework_id: "cis_v8",
        control_id: "1.11",
        title: "Cryptographic Controls",
        description: "Establish and maintain cryptographic controls to protect data in transit and at rest.",
        family: "Cryptography",
        priority: "IG2",
        supplemental_guidance: "Use approved cryptographic algorithms and avoid weak functions.",
        related_controls: ["1.11.1"],
        external_references: {
            "nist": "SC-13",
            "iso": "A.10.1.1"
        }
    },
    {
        framework_id: "cis_v8",
        control_id: "8.2",
        title: "Collect Audit Logs",
        description: "Collect audit logs from enterprise assets and software, where possible, and review on a regular basis.",
        family: "Logging and Monitoring",
        priority: "IG1",
        supplemental_guidance: "Regular review helps detect security incidents and compliance violations.",
        related_controls: ["8.1"],
        external_references: {
            "nist": "AU-2",
            "iso": "A.12.4.1"
        }
    }
];

// Insert NIST controls
print('Inserting NIST 800-53 R5 controls...');
try {
    const nistResult = db.framework_control_definitions.insertMany(nistControls, { ordered: false });
    print(`Inserted ${nistResult.insertedIds.length} NIST 800-53 R5 controls`);
} catch (error) {
    print(`Error inserting NIST controls: ${error.message}`);
}

// Insert CIS controls
print('Inserting CIS v8 controls...');
try {
    const cisResult = db.framework_control_definitions.insertMany(cisControls, { ordered: false });
    print(`Inserted ${cisResult.insertedIds.length} CIS v8 controls`);
} catch (error) {
    print(`Error inserting CIS controls: ${error.message}`);
}

// Create framework metadata collection
print('Creating framework metadata collection...');
db.createCollection('framework_metadata');

db.framework_metadata.createIndex(
    { "framework_id": 1 }, 
    { "unique": true, "name": "idx_framework_metadata_id" }
);

// Insert framework metadata
const frameworkMetadata = [
    {
        framework_id: "nist_800_53_r5",
        name: "NIST Special Publication 800-53 Revision 5",
        description: "Security and Privacy Controls for Information Systems and Organizations",
        version: "5.1.1",
        published_date: new Date("2020-09-23"),
        updated_date: new Date("2022-12-01"),
        organization: "National Institute of Standards and Technology",
        url: "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final",
        control_families: [
            "Access Control (AC)",
            "Awareness and Training (AT)", 
            "Audit and Accountability (AU)",
            "Configuration Management (CM)",
            "Contingency Planning (CP)",
            "Identification and Authentication (IA)",
            "Incident Response (IR)",
            "Maintenance (MA)",
            "Media Protection (MP)",
            "Physical and Environmental Protection (PE)",
            "Planning (PL)",
            "Program Management (PM)",
            "Personnel Security (PS)",
            "Privacy Controls (PT)",
            "Risk Assessment (RA)",
            "System and Communications Protection (SC)",
            "System and Information Integrity (SI)",
            "System and Services Acquisition (SA)",
            "Supply Chain Risk Management (SR)"
        ]
    },
    {
        framework_id: "cis_v8",
        name: "CIS Controls Version 8",
        description: "A prioritized set of actions for cybersecurity that form a defense-in-depth set of best practices",
        version: "8.0",
        published_date: new Date("2021-05-18"),
        updated_date: new Date("2021-05-18"),
        organization: "Center for Internet Security",
        url: "https://www.cisecurity.org/controls/v8",
        implementation_groups: [
            {
                "group": "IG1",
                "description": "Basic cyber hygiene for small to medium enterprises with limited cybersecurity expertise"
            },
            {
                "group": "IG2", 
                "description": "Broader security program for enterprises with moderate cybersecurity risk management program"
            },
            {
                "group": "IG3",
                "description": "Advanced security program for enterprises with significant cybersecurity risk management program"
            }
        ]
    }
];

try {
    const metadataResult = db.framework_metadata.insertMany(frameworkMetadata, { ordered: false });
    print(`Inserted ${metadataResult.insertedIds.length} framework metadata records`);
} catch (error) {
    print(`Error inserting framework metadata: ${error.message}`);
}

// Display summary
print('\n=== Framework Control Definitions Summary ===');
print(`NIST 800-53 R5 controls: ${db.framework_control_definitions.countDocuments({framework_id: "nist_800_53_r5"})}`);
print(`CIS v8 controls: ${db.framework_control_definitions.countDocuments({framework_id: "cis_v8"})}`);
print(`Total controls: ${db.framework_control_definitions.countDocuments({})}`);
print(`Framework metadata records: ${db.framework_metadata.countDocuments({})}`);

print('Framework control definitions initialization completed successfully!');