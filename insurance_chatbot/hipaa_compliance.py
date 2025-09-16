"""
HIPAA Compliance Module for Insurance Chatbot
Implements comprehensive HIPAA compliance features including:
- User consent management
- Data deletion capabilities
- Privacy policy integration
- Data export/portability
- Right to be forgotten
- Data minimization
"""

import os
import json
import sqlite3
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from security import security_manager
import uuid

class HIPAAComplianceManager:
    """Manages HIPAA compliance features for the insurance chatbot"""
    
    def __init__(self):
        self.consent_db = "consent_records.db"
        self.privacy_policy_version = "1.0"
        self.data_retention_days = 2555  # 7 years for HIPAA
        self._init_consent_database()
    
    def _init_consent_database(self):
        """Initialize consent tracking database"""
        with sqlite3.connect(self.consent_db) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS user_consent (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    consent_type TEXT NOT NULL,
                    consent_given BOOLEAN NOT NULL,
                    consent_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    ip_address TEXT,
                    user_agent TEXT,
                    consent_version TEXT,
                    data_processing_purposes TEXT,
                    retention_period_days INTEGER,
                    withdrawal_timestamp DATETIME,
                    withdrawal_reason TEXT
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS data_processing_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id TEXT NOT NULL,
                    data_type TEXT NOT NULL,
                    processing_purpose TEXT NOT NULL,
                    legal_basis TEXT NOT NULL,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    data_retention_until DATETIME,
                    anonymized BOOLEAN DEFAULT FALSE
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS data_deletion_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id TEXT NOT NULL,
                    deletion_type TEXT NOT NULL,
                    deletion_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    data_categories TEXT,
                    retention_exception BOOLEAN DEFAULT FALSE,
                    legal_hold BOOLEAN DEFAULT FALSE,
                    deletion_reason TEXT
                )
            """)
    
    def get_privacy_policy(self) -> Dict[str, Any]:
        """Get current privacy policy"""
        return {
            "version": self.privacy_policy_version,
            "last_updated": "2025-09-15",
            "data_collection": {
                "types": ["chat_queries", "responses", "session_data", "analytics_data"],
                "purposes": ["service_provision", "analytics", "security", "compliance"],
                "legal_basis": "legitimate_interest",
                "retention_period": "7_years"
            },
            "user_rights": {
                "access": "Request copy of your data",
                "rectification": "Correct inaccurate data",
                "erasure": "Request data deletion",
                "portability": "Export your data",
                "objection": "Object to data processing",
                "restriction": "Limit data processing"
            },
            "data_sharing": {
                "third_parties": "None - data stays local",
                "international_transfers": "None",
                "law_enforcement": "Only with valid legal process"
            },
            "security_measures": {
                "encryption": "AES-256 encryption at rest and in transit",
                "access_controls": "Role-based access with audit logging",
                "data_minimization": "Only collect necessary data",
                "anonymization": "Data anonymized for analytics"
            },
            "contact_info": {
                "dpo_email": "privacy@insurance-chatbot.com",
                "response_time": "30_days"
            }
        }
    
    def request_consent(self, user_id: str, session_id: str, consent_type: str, 
                       ip_address: str = None, user_agent: str = None) -> Dict[str, Any]:
        """Request user consent for data processing"""
        
        consent_data = {
            "consent_id": str(uuid.uuid4()),
            "user_id": user_id,
            "session_id": session_id,
            "consent_type": consent_type,
            "privacy_policy": self.get_privacy_policy(),
            "data_collection": {
                "what": "Chat queries, responses, and usage analytics",
                "why": "To provide insurance information and improve service",
                "how_long": "7 years (HIPAA requirement)",
                "who": "Only our organization - no third parties"
            },
            "user_rights": [
                "Access your data",
                "Correct errors",
                "Delete your data",
                "Export your data",
                "Withdraw consent anytime"
            ],
            "timestamp": datetime.now().isoformat()
        }
        
        # Log consent request
        security_manager.log_access(user_id, "consent_request", "privacy", True)
        
        return consent_data
    
    def record_consent(self, user_id: str, session_id: str, consent_type: str,
                      consent_given: bool, ip_address: str = None, 
                      user_agent: str = None, purposes: List[str] = None) -> bool:
        """Record user consent decision"""
        
        if purposes is None:
            purposes = ["service_provision", "analytics", "security"]
        
        try:
            with sqlite3.connect(self.consent_db) as conn:
                conn.execute("""
                    INSERT INTO user_consent 
                    (user_id, session_id, consent_type, consent_given, ip_address, 
                     user_agent, consent_version, data_processing_purposes, retention_period_days)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    user_id, session_id, consent_type, consent_given,
                    ip_address, user_agent, self.privacy_policy_version,
                    json.dumps(purposes), self.data_retention_days
                ))
            
            # Log consent decision
            action = "consent_granted" if consent_given else "consent_denied"
            security_manager.log_access(user_id, action, "privacy", True)
            
            return True
            
        except Exception as e:
            security_manager.log_access(user_id, "consent_error", "privacy", False)
            print(f"Error recording consent: {e}")
            return False
    
    def check_consent(self, user_id: str, consent_type: str = "data_processing") -> bool:
        """Check if user has given consent for data processing"""
        try:
            with sqlite3.connect(self.consent_db) as conn:
                cursor = conn.execute("""
                    SELECT consent_given, consent_timestamp, withdrawal_timestamp
                    FROM user_consent 
                    WHERE user_id = ? AND consent_type = ?
                    ORDER BY consent_timestamp DESC
                    LIMIT 1
                """, (user_id, consent_type))
                
                result = cursor.fetchone()
                if not result:
                    return False
                
                consent_given, consent_time, withdrawal_time = result
                
                # Check if consent was withdrawn
                if withdrawal_time:
                    return False
                
                # Check if consent is still valid (not expired)
                consent_date = datetime.fromisoformat(consent_time)
                if datetime.now() - consent_date > timedelta(days=self.data_retention_days):
                    return False
                
                return bool(consent_given)
                
        except Exception as e:
            print(f"Error checking consent: {e}")
            return False
    
    def withdraw_consent(self, user_id: str, consent_type: str = "data_processing",
                        reason: str = "User request") -> bool:
        """Allow user to withdraw consent"""
        try:
            with sqlite3.connect(self.consent_db) as conn:
                conn.execute("""
                    UPDATE user_consent 
                    SET withdrawal_timestamp = ?, withdrawal_reason = ?
                    WHERE user_id = ? AND consent_type = ? AND withdrawal_timestamp IS NULL
                """, (datetime.now().isoformat(), reason, user_id, consent_type))
            
            # Log consent withdrawal
            security_manager.log_access(user_id, "consent_withdrawn", "privacy", True)
            
            return True
            
        except Exception as e:
            security_manager.log_access(user_id, "consent_withdrawal_error", "privacy", False)
            print(f"Error withdrawing consent: {e}")
            return False
    
    def export_user_data(self, user_id: str) -> Dict[str, Any]:
        """Export all user data for portability"""
        try:
            # Get user's chat data
            db_path = os.path.join(os.path.dirname(__file__), "queries.db")
            with sqlite3.connect(db_path) as conn:
                cursor = conn.execute("""
                    SELECT query, answer, timestamp, category
                    FROM queries 
                    WHERE user_id = ?
                    ORDER BY timestamp DESC
                """, (user_id,))
                
                chat_data = []
                for row in cursor.fetchall():
                    # Decrypt data if possible
                    try:
                        cipher = security_manager.get_cipher()
                        if cipher:
                            query = cipher.decrypt(row[0].encode()).decode()
                            answer = cipher.decrypt(row[1].encode()).decode()
                        else:
                            query = row[0]
                            answer = row[1]
                    except:
                        query = "[ENCRYPTED]"
                        answer = "[ENCRYPTED]"
                    
                    chat_data.append({
                        "query": query,
                        "answer": answer,
                        "timestamp": row[2],
                        "category": row[3]
                    })
            
            # Get consent data
            with sqlite3.connect(self.consent_db) as conn:
                cursor = conn.execute("""
                    SELECT consent_type, consent_given, consent_timestamp, 
                           withdrawal_timestamp, data_processing_purposes
                    FROM user_consent 
                    WHERE user_id = ?
                    ORDER BY consent_timestamp DESC
                """, (user_id,))
                
                consent_data = []
                for row in cursor.fetchall():
                    consent_data.append({
                        "consent_type": row[0],
                        "consent_given": bool(row[1]),
                        "consent_timestamp": row[2],
                        "withdrawal_timestamp": row[3],
                        "purposes": json.loads(row[4]) if row[4] else []
                    })
            
            export_data = {
                "user_id": user_id,
                "export_timestamp": datetime.now().isoformat(),
                "data_categories": {
                    "chat_interactions": chat_data,
                    "consent_records": consent_data
                },
                "privacy_policy": self.get_privacy_policy(),
                "data_rights": {
                    "access": "You can request a copy of this data anytime",
                    "rectification": "You can request corrections to this data",
                    "erasure": "You can request deletion of this data",
                    "portability": "This export provides your data in a portable format"
                }
            }
            
            # Log data export
            security_manager.log_access(user_id, "data_export", "privacy", True)
            
            return export_data
            
        except Exception as e:
            security_manager.log_access(user_id, "data_export_error", "privacy", False)
            print(f"Error exporting user data: {e}")
            return {"error": "Failed to export user data"}
    
    def delete_user_data(self, user_id: str, deletion_type: str = "full",
                        reason: str = "User request") -> Dict[str, Any]:
        """Delete user data (with HIPAA compliance considerations)"""
        try:
            deletion_log = {
                "user_id": user_id,
                "deletion_type": deletion_type,
                "timestamp": datetime.now().isoformat(),
                "data_categories": [],
                "retention_exceptions": [],
                "legal_hold": False
            }
            
            # Check for legal hold (simplified - in production, check against legal hold database)
            legal_hold = False
            
            if legal_hold:
                return {
                    "success": False,
                    "reason": "Data subject to legal hold - cannot be deleted",
                    "legal_hold": True
                }
            
            # Delete chat data
            db_path = os.path.join(os.path.dirname(__file__), "queries.db")
            with sqlite3.connect(db_path) as conn:
                cursor = conn.execute("SELECT COUNT(*) FROM queries WHERE user_id = ?", (user_id,))
                chat_count = cursor.fetchone()[0]
                
                if chat_count > 0:
                    conn.execute("DELETE FROM queries WHERE user_id = ?", (user_id,))
                    deletion_log["data_categories"].append(f"chat_data: {chat_count} records")
            
            # Delete consent data (with retention exception for compliance)
            with sqlite3.connect(self.consent_db) as conn:
                # Keep consent records for compliance but mark as deleted
                conn.execute("""
                    UPDATE user_consent 
                    SET withdrawal_timestamp = ?, withdrawal_reason = ?
                    WHERE user_id = ? AND withdrawal_timestamp IS NULL
                """, (datetime.now().isoformat(), f"Data deletion: {reason}", user_id))
                
                deletion_log["retention_exceptions"].append("consent_records: retained for compliance")
            
            # Log deletion
            with sqlite3.connect(self.consent_db) as conn:
                conn.execute("""
                    INSERT INTO data_deletion_log 
                    (user_id, deletion_type, data_categories, deletion_reason)
                    VALUES (?, ?, ?, ?)
                """, (user_id, deletion_type, json.dumps(deletion_log["data_categories"]), reason))
            
            # Log deletion action
            security_manager.log_access(user_id, "data_deletion", "privacy", True)
            
            deletion_log["success"] = True
            deletion_log["message"] = "User data deleted successfully (consent records retained for compliance)"
            
            return deletion_log
            
        except Exception as e:
            security_manager.log_access(user_id, "data_deletion_error", "privacy", False)
            print(f"Error deleting user data: {e}")
            return {"success": False, "error": str(e)}
    
    def anonymize_data(self, user_id: str) -> bool:
        """Anonymize user data while preserving analytics value"""
        try:
            cipher = security_manager.get_cipher()
            if not cipher:
                return False
            
            db_path = os.path.join(os.path.dirname(__file__), "queries.db")
            with sqlite3.connect(db_path) as conn:
                # Get user's data
                cursor = conn.execute("""
                    SELECT id, query, answer FROM queries WHERE user_id = ?
                """, (user_id,))
                
                for row in cursor.fetchall():
                    record_id, encrypted_query, encrypted_answer = row
                    
                    try:
                        # Decrypt data
                        query = cipher.decrypt(encrypted_query.encode()).decode()
                        answer = cipher.decrypt(encrypted_answer.encode()).decode()
                        
                        # Anonymize
                        anonymized_query = security_manager.anonymize_data(query)
                        anonymized_answer = security_manager.anonymize_data(answer)
                        
                        # Re-encrypt anonymized data
                        new_encrypted_query = cipher.encrypt(anonymized_query.encode()).decode()
                        new_encrypted_answer = cipher.encrypt(anonymized_answer.encode()).decode()
                        
                        # Update record
                        conn.execute("""
                            UPDATE queries 
                            SET query = ?, answer = ?, user_id = 'ANONYMIZED'
                            WHERE id = ?
                        """, (new_encrypted_query, new_encrypted_answer, record_id))
                        
                    except Exception as e:
                        print(f"Error anonymizing record {record_id}: {e}")
                        continue
                
                conn.commit()
            
            # Log anonymization
            security_manager.log_access(user_id, "data_anonymization", "privacy", True)
            
            return True
            
        except Exception as e:
            security_manager.log_access(user_id, "data_anonymization_error", "privacy", False)
            print(f"Error anonymizing data: {e}")
            return False
    
    def get_compliance_status(self) -> Dict[str, Any]:
        """Get current HIPAA compliance status"""
        try:
            with sqlite3.connect(self.consent_db) as conn:
                # Get consent statistics
                cursor = conn.execute("""
                    SELECT 
                        COUNT(*) as total_consents,
                        SUM(CASE WHEN consent_given = 1 THEN 1 ELSE 0 END) as consents_given,
                        SUM(CASE WHEN withdrawal_timestamp IS NOT NULL THEN 1 ELSE 0 END) as consents_withdrawn
                    FROM user_consent
                """)
                consent_stats = cursor.fetchone()
                
                # Get data processing stats
                cursor = conn.execute("""
                    SELECT COUNT(*) FROM data_processing_log
                """)
                processing_count = cursor.fetchone()[0]
                
                # Get deletion stats
                cursor = conn.execute("""
                    SELECT COUNT(*) FROM data_deletion_log
                """)
                deletion_count = cursor.fetchone()[0]
            
            return {
                "compliance_status": "ACTIVE",
                "privacy_policy_version": self.privacy_policy_version,
                "data_retention_days": self.data_retention_days,
                "consent_statistics": {
                    "total_consents": consent_stats[0],
                    "consents_given": consent_stats[1],
                    "consents_withdrawn": consent_stats[2]
                },
                "data_processing_logs": processing_count,
                "data_deletion_logs": deletion_count,
                "last_updated": datetime.now().isoformat()
            }
            
        except Exception as e:
            print(f"Error getting compliance status: {e}")
            return {"error": "Failed to get compliance status"}

# Global HIPAA compliance manager
hipaa_manager = HIPAAComplianceManager()
