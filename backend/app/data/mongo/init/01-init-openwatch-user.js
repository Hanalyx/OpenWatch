// MongoDB initialization script for OpenWatch compliance rules
// Creates database, user, and initial indexes

// Switch to admin database for user creation
db = db.getSiblingDB('admin');

// Create openwatch user if it doesn't exist
try {
    db.createUser({
        user: 'openwatch',
        pwd: process.env.MONGO_ROOT_PASSWORD || 'secure_mongo_password',
        roles: [
            {
                role: 'readWrite',
                db: 'openwatch_rules'
            },
            {
                role: 'dbAdmin',
                db: 'openwatch_rules'
            }
        ]
    });
    print('Created openwatch user successfully');
} catch (error) {
    if (error.code !== 11000) { // Ignore duplicate user error
        print('Error creating user: ' + error.message);
        throw error;
    } else {
        print('User openwatch already exists, skipping creation');
    }
}

// Switch to openwatch_rules database
db = db.getSiblingDB('openwatch_rules');

// Create initial collections with validation
try {
    // Compliance Rules collection
    db.createCollection('compliance_rules', {
        validator: {
            $jsonSchema: {
                bsonType: 'object',
                required: ['rule_id', 'metadata', 'severity', 'category'],
                properties: {
                    rule_id: {
                        bsonType: 'string',
                        description: 'Unique OpenWatch rule identifier'
                    },
                    scap_rule_id: {
                        bsonType: 'string',
                        description: 'Original SCAP rule identifier'
                    },
                    metadata: {
                        bsonType: 'object',
                        required: ['name'],
                        properties: {
                            name: {
                                bsonType: 'string',
                                description: 'Human-readable rule name'
                            },
                            description: {
                                bsonType: 'string'
                            },
                            source: {
                                bsonType: 'object'
                            }
                        }
                    },
                    severity: {
                        bsonType: 'string',
                        enum: ['info', 'low', 'medium', 'high', 'critical'],
                        description: 'Rule severity level'
                    },
                    category: {
                        bsonType: 'string',
                        description: 'Rule category (authentication, access_control, etc.)'
                    }
                }
            }
        }
    });
    print('Created compliance_rules collection with validation');
} catch (error) {
    print('Error creating compliance_rules collection: ' + error.message);
}

try {
    // Rule Intelligence collection
    db.createCollection('rule_intelligence', {
        validator: {
            $jsonSchema: {
                bsonType: 'object',
                required: ['rule_id'],
                properties: {
                    rule_id: {
                        bsonType: 'string',
                        description: 'Reference to compliance rule'
                    },
                    business_impact: {
                        bsonType: 'string'
                    },
                    false_positive_rate: {
                        bsonType: 'double',
                        minimum: 0.0,
                        maximum: 1.0
                    }
                }
            }
        }
    });
    print('Created rule_intelligence collection with validation');
} catch (error) {
    print('Error creating rule_intelligence collection: ' + error.message);
}

try {
    // Remediation Scripts collection
    db.createCollection('remediation_scripts', {
        validator: {
            $jsonSchema: {
                bsonType: 'object',
                required: ['rule_id', 'platform', 'script_type'],
                properties: {
                    rule_id: {
                        bsonType: 'string'
                    },
                    platform: {
                        bsonType: 'string'
                    },
                    script_type: {
                        bsonType: 'string',
                        enum: ['bash', 'python', 'ansible', 'powershell']
                    }
                }
            }
        }
    });
    print('Created remediation_scripts collection with validation');
} catch (error) {
    print('Error creating remediation_scripts collection: ' + error.message);
}

// Create indexes for optimal performance
print('Creating indexes for compliance_rules collection...');

// Primary indexes
try {
    db.compliance_rules.createIndex({ 'rule_id': 1 }, { unique: true, name: 'idx_rule_id' });
    db.compliance_rules.createIndex({ 'scap_rule_id': 1 }, { name: 'idx_scap_rule_id' });
    
    // Multi-platform queries
    db.compliance_rules.createIndex(
        { 'platform_implementations.rhel.versions': 1, 'severity': -1 },
        { name: 'idx_rhel_versions_severity' }
    );
    db.compliance_rules.createIndex(
        { 'platform_implementations.ubuntu.versions': 1, 'severity': -1 },
        { name: 'idx_ubuntu_versions_severity' }
    );
    db.compliance_rules.createIndex(
        { 'platform_implementations.windows.versions': 1, 'severity': -1 },
        { name: 'idx_windows_versions_severity' }
    );
    
    // Framework version queries
    db.compliance_rules.createIndex({ 'frameworks.nist.800-53r4': 1 }, { name: 'idx_nist_r4' });
    db.compliance_rules.createIndex({ 'frameworks.nist.800-53r5': 1 }, { name: 'idx_nist_r5' });
    db.compliance_rules.createIndex({ 'frameworks.cis.rhel8_v2.0.0': 1 }, { name: 'idx_cis_rhel8' });
    db.compliance_rules.createIndex({ 'frameworks.stig.rhel8_v1r11': 1 }, { name: 'idx_stig_rhel8' });
    db.compliance_rules.createIndex({ 'frameworks.stig.rhel9_v1r1': 1 }, { name: 'idx_stig_rhel9' });
    
    // Inheritance and capability queries
    db.compliance_rules.createIndex({ 'inherits_from': 1 }, { name: 'idx_inheritance' });
    db.compliance_rules.createIndex(
        { 'abstract': 1, 'category': 1 },
        { name: 'idx_abstract_category' }
    );
    db.compliance_rules.createIndex(
        { 'platform_requirements.required_capabilities': 1 },
        { name: 'idx_capabilities' }
    );
    
    // Standard queries
    db.compliance_rules.createIndex(
        { 'category': 1, 'severity': -1 },
        { name: 'idx_category_severity' }
    );
    db.compliance_rules.createIndex({ 'tags': 1 }, { name: 'idx_tags' });
    db.compliance_rules.createIndex({ 'security_function': 1 }, { name: 'idx_security_function' });
    db.compliance_rules.createIndex({ 'updated_at': -1 }, { name: 'idx_updated_at' });
    
    print('Successfully created all compliance_rules indexes');
} catch (error) {
    print('Error creating compliance_rules indexes: ' + error.message);
}

// Create indexes for rule_intelligence
print('Creating indexes for rule_intelligence collection...');
try {
    db.rule_intelligence.createIndex({ 'rule_id': 1 }, { unique: true, name: 'idx_ri_rule_id' });
    db.rule_intelligence.createIndex({ 'business_impact': 1 }, { name: 'idx_ri_business_impact' });
    db.rule_intelligence.createIndex({ 'false_positive_rate': 1 }, { name: 'idx_ri_false_positive' });
    db.rule_intelligence.createIndex({ 'last_validation': -1 }, { name: 'idx_ri_last_validation' });
    
    print('Successfully created rule_intelligence indexes');
} catch (error) {
    print('Error creating rule_intelligence indexes: ' + error.message);
}

// Create indexes for remediation_scripts
print('Creating indexes for remediation_scripts collection...');
try {
    db.remediation_scripts.createIndex(
        { 'rule_id': 1, 'platform': 1 },
        { name: 'idx_rs_rule_platform' }
    );
    db.remediation_scripts.createIndex({ 'script_type': 1 }, { name: 'idx_rs_script_type' });
    db.remediation_scripts.createIndex({ 'approved': 1 }, { name: 'idx_rs_approved' });
    
    print('Successfully created remediation_scripts indexes');
} catch (error) {
    print('Error creating remediation_scripts indexes: ' + error.message);
}

// Create text indexes for full-text search
print('Creating text indexes for search functionality...');
try {
    db.compliance_rules.createIndex(
        {
            'metadata.name': 'text',
            'metadata.description': 'text',
            'tags': 'text'
        },
        {
            name: 'idx_text_search',
            weights: {
                'metadata.name': 10,
                'metadata.description': 5,
                'tags': 2
            }
        }
    );
    
    print('Successfully created text search indexes');
} catch (error) {
    print('Error creating text search indexes: ' + error.message);
}

// Insert a test document to verify everything works
try {
    const testRule = {
        rule_id: 'ow-test-connection',
        scap_rule_id: 'test_connection_rule',
        metadata: {
            name: 'MongoDB Connection Test Rule',
            description: 'Test rule to verify MongoDB connectivity and schema validation',
            source: {
                upstream_id: 'test_connection',
                source_file: 'init_script',
                imported_at: new Date().toISOString()
            }
        },
        severity: 'info',
        category: 'testing',
        security_function: 'connection_test',
        tags: ['test', 'mongodb', 'connection'],
        frameworks: {
            nist: {
                '800-53r5': ['SI-11']
            }
        },
        platform_implementations: {
            rhel: {
                versions: ['8.0', '8.1', '8.2'],
                check_method: 'test'
            }
        },
        check_type: 'test',
        check_content: {
            test_type: 'connection',
            expected_result: 'success'
        },
        fix_available: false,
        source_file: 'init_script.js',
        source_hash: 'test_hash_' + Date.now(),
        version: '1.0.0',
        imported_at: new Date(),
        updated_at: new Date()
    };
    
    const result = db.compliance_rules.insertOne(testRule);
    print('Successfully inserted test rule with ID: ' + result.insertedId);
} catch (error) {
    print('Error inserting test rule: ' + error.message);
}

print('MongoDB initialization completed successfully');
print('Database: openwatch_rules');
print('Collections created: compliance_rules, rule_intelligence, remediation_scripts');
print('Indexes created: ' + db.compliance_rules.getIndexes().length + ' compliance_rules, ' + 
      db.rule_intelligence.getIndexes().length + ' rule_intelligence, ' + 
      db.remediation_scripts.getIndexes().length + ' remediation_scripts');