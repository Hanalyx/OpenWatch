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
    // Ignore if user already exists (check error message and string representation)
    var errorStr = error.toString();
    var errorMsg = error.message || '';
    if (errorStr.indexOf('already exists') !== -1 || errorMsg.indexOf('already exists') !== -1) {
        print('User openwatch already exists, skipping creation');
    } else {
        print('Error creating user: ' + errorStr);
        throw error;
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
                        bsonType: ['string', 'null'],
                        description: 'Original SCAP rule identifier (optional, can be null for non-SCAP rules)'
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

// ============================================================================
// INDEX MANAGEMENT MIGRATED TO BEANIE ODM (2025-10-26)
// ============================================================================
// All MongoDB indexes are now managed by Beanie ODM in backend/app/models/mongo_models.py
// This ensures:
// - Single source of truth for index definitions
// - Automatic index creation/updates on application startup
// - No naming conflicts between init script and ODM
// - Version control for index changes
//
// Collections with indexes managed by Beanie:
// - compliance_rules (17 indexes including text search)
// - rule_intelligence (6 indexes including unique rule_id)
// - remediation_scripts (3 indexes)
//
// For index modifications, edit the Settings.indexes array in mongo_models.py
// ============================================================================
print('Indexes are managed by Beanie ODM - see backend/app/models/mongo_models.py');

// ============================================================================
// TEST DATA REMOVED (2025-10-26)
// ============================================================================
// Previous versions of this script inserted a test rule to verify connectivity.
// This has been removed to keep the database clean.
// Real compliance rules are imported via the upload API or CLI converter.
// ============================================================================

print('MongoDB initialization completed successfully');
print('Database: openwatch_rules');
print('Collections created: compliance_rules, rule_intelligence, remediation_scripts');
print('Indexes created: ' + db.compliance_rules.getIndexes().length + ' compliance_rules, ' + 
      db.rule_intelligence.getIndexes().length + ' rule_intelligence, ' + 
      db.remediation_scripts.getIndexes().length + ' remediation_scripts');