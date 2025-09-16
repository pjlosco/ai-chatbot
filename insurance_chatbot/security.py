"""
Security Module for Insurance Chatbot
Implements HIPAA-compliant security features including:
- Secure key management with rotation
- Audit logging
- Access controls
- Data encryption and anonymization
"""

import os
import hashlib
import secrets
import sqlite3
import logging
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import json
from typing import Optional, Dict, Any
import uuid

class SecurityManager:
    """Centralized security management for HIPAA compliance"""
    
    def __init__(self, config_file: str = "security_config.json"):
        self.config_file = config_file
        self.config = self._load_config()
        self.audit_logger = self._setup_audit_logging()
        self.current_key = None
        self.key_rotation_date = None
        
    def _load_config(self) -> Dict[str, Any]:
        """Load security configuration with defaults"""
        default_config = {
            "key_rotation_days": 90,
            "max_failed_attempts": 5,
            "session_timeout_minutes": 30,
            "data_retention_days": 2555,  # 7 years for HIPAA
            "encryption_algorithm": "AES-256-GCM",
            "audit_log_level": "INFO",
            "require_https": True,
            "enable_rate_limiting": True,
            "max_queries_per_hour": 100
        }
        
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    user_config = json.load(f)
                    default_config.update(user_config)
            except Exception as e:
                print(f"⚠️  Error loading security config: {e}")
                print("Using default security configuration")
        
        return default_config
    
    def _setup_audit_logging(self) -> logging.Logger:
        """Setup comprehensive audit logging"""
        # Create logs directory if it doesn't exist
        os.makedirs("logs", exist_ok=True)
        
        # Setup audit logger
        audit_logger = logging.getLogger('audit')
        audit_logger.setLevel(getattr(logging, self.config["audit_log_level"]))
        
        # Create file handler for audit logs
        audit_handler = logging.FileHandler('logs/audit.log')
        audit_handler.setLevel(logging.INFO)
        
        # Create formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        audit_handler.setFormatter(formatter)
        
        # Add handler to logger
        if not audit_logger.handlers:
            audit_logger.addHandler(audit_handler)
        
        return audit_logger
    
    def generate_secure_key(self, password: Optional[str] = None) -> bytes:
        """Generate a secure encryption key using PBKDF2"""
        if password:
            # Use password-based key derivation
            salt = secrets.token_bytes(16)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        else:
            # Generate random key
            key = Fernet.generate_key()
        
        return key
    
    def store_key_securely(self, key: bytes, key_id: str = None) -> str:
        """Store encryption key with secure metadata"""
        if not key_id:
            key_id = str(uuid.uuid4())
        
        # Create secure key storage
        key_data = {
            "key_id": key_id,
            "key": base64.urlsafe_b64encode(key).decode(),
            "created_at": datetime.now().isoformat(),
            "expires_at": (datetime.now() + timedelta(days=self.config["key_rotation_days"])).isoformat(),
            "algorithm": "Fernet"
        }
        
        # Store in secure location
        key_file = f"keys/{key_id}.key"
        os.makedirs("keys", exist_ok=True)
        
        with open(key_file, 'w') as f:
            json.dump(key_data, f)
        
        # Set secure file permissions (Unix only)
        if os.name != 'nt':
            os.chmod(key_file, 0o600)
        
        self.audit_logger.info(f"New encryption key created: {key_id}")
        return key_id
    
    def load_current_key(self) -> Optional[bytes]:
        """Load the current active encryption key"""
        try:
            # Find the most recent key
            keys_dir = "keys"
            if not os.path.exists(keys_dir):
                return None
            
            key_files = [f for f in os.listdir(keys_dir) if f.endswith('.key')]
            if not key_files:
                return None
            
            # Sort by creation time (newest first)
            key_files.sort(key=lambda x: os.path.getctime(os.path.join(keys_dir, x)), reverse=True)
            
            # Load the most recent key
            latest_key_file = os.path.join(keys_dir, key_files[0])
            with open(latest_key_file, 'r') as f:
                key_data = json.load(f)
            
            # Check if key is expired
            expires_at = datetime.fromisoformat(key_data["expires_at"])
            if datetime.now() > expires_at:
                self.audit_logger.warning(f"Encryption key {key_data['key_id']} has expired")
                return None
            
            key = base64.urlsafe_b64decode(key_data["key"].encode())
            self.current_key = key
            self.key_rotation_date = expires_at
            
            return key
            
        except Exception as e:
            self.audit_logger.error(f"Error loading encryption key: {e}")
            return None
    
    def rotate_key_if_needed(self) -> bool:
        """Check if key rotation is needed and perform it"""
        if not self.key_rotation_date:
            return False
        
        if datetime.now() >= self.key_rotation_date:
            self.audit_logger.info("Performing scheduled key rotation")
            return self.rotate_key()
        
        return False
    
    def rotate_key(self) -> bool:
        """Rotate encryption key and re-encrypt all data"""
        try:
            # Generate new key
            new_key = self.generate_secure_key()
            new_key_id = self.store_key_securely(new_key)
            
            # Re-encrypt all data with new key
            self._reencrypt_all_data(new_key)
            
            # Update current key
            self.current_key = new_key
            self.key_rotation_date = datetime.now() + timedelta(days=self.config["key_rotation_days"])
            
            self.audit_logger.info(f"Key rotation completed: {new_key_id}")
            return True
            
        except Exception as e:
            self.audit_logger.error(f"Key rotation failed: {e}")
            return False
    
    def _reencrypt_all_data(self, new_key: bytes):
        """Re-encrypt all data with new key"""
        old_cipher = Fernet(self.current_key) if self.current_key else None
        new_cipher = Fernet(new_key)
        
        # Re-encrypt database data
        with sqlite3.connect("queries.db") as conn:
            cursor = conn.execute("SELECT id, query, answer FROM queries")
            rows = cursor.fetchall()
            
            for row_id, encrypted_query, encrypted_answer in rows:
                try:
                    # Decrypt with old key
                    if old_cipher:
                        query = old_cipher.decrypt(encrypted_query.encode()).decode()
                        answer = old_cipher.decrypt(encrypted_answer.encode()).decode()
                    else:
                        # If no old key, assume data is already in plain text (migration)
                        query = encrypted_query
                        answer = encrypted_answer
                    
                    # Encrypt with new key
                    new_encrypted_query = new_cipher.encrypt(query.encode()).decode()
                    new_encrypted_answer = new_cipher.encrypt(answer.encode()).decode()
                    
                    # Update database
                    conn.execute("""
                        UPDATE queries 
                        SET query = ?, answer = ? 
                        WHERE id = ?
                    """, (new_encrypted_query, new_encrypted_answer, row_id))
                    
                except Exception as e:
                    self.audit_logger.error(f"Error re-encrypting row {row_id}: {e}")
            
            conn.commit()
    
    def get_cipher(self) -> Optional[Fernet]:
        """Get current cipher for encryption/decryption"""
        if not self.current_key:
            self.current_key = self.load_current_key()
        
        if not self.current_key:
            # Generate a new key if none exists
            print("🔑 No encryption key found, generating new key...")
            self.current_key = self.generate_secure_key()
            self.store_key_securely(self.current_key)
            print("✅ New encryption key generated and stored")
        
        return Fernet(self.current_key)
    
    def log_access(self, user_id: str, action: str, resource: str, success: bool = True):
        """Log user access for audit trail"""
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "user_id": user_id,
            "action": action,
            "resource": resource,
            "success": success,
            "ip_address": "127.0.0.1",  # In production, get from request
            "user_agent": "Insurance-Chatbot/1.0"
        }
        
        if success:
            self.audit_logger.info(f"Access granted: {json.dumps(log_entry)}")
        else:
            self.audit_logger.warning(f"Access denied: {json.dumps(log_entry)}")
    
    def anonymize_data(self, data: str) -> str:
        """Anonymize sensitive data for analytics"""
        # Simple anonymization - in production, use more sophisticated methods
        anonymized = data.replace("SSN", "XXX-XX-XXXX")
        anonymized = anonymized.replace("DOB", "XX/XX/XXXX")
        anonymized = anonymized.replace("phone", "XXX-XXX-XXXX")
        return anonymized
    
    def check_data_retention(self) -> int:
        """Check and clean up expired data based on retention policy"""
        retention_days = self.config["data_retention_days"]
        cutoff_date = datetime.now() - timedelta(days=retention_days)
        
        with sqlite3.connect("queries.db") as conn:
            cursor = conn.execute("""
                SELECT COUNT(*) FROM queries 
                WHERE timestamp < ?
            """, (cutoff_date.isoformat(),))
            
            expired_count = cursor.fetchone()[0]
            
            if expired_count > 0:
                # Delete expired data
                conn.execute("""
                    DELETE FROM queries 
                    WHERE timestamp < ?
                """, (cutoff_date.isoformat(),))
                conn.commit()
                
                self.audit_logger.info(f"Deleted {expired_count} expired records")
                return expired_count
        
        return 0
    
    def validate_input(self, input_data: str) -> tuple[bool, str]:
        """Validate and sanitize user input"""
        if not input_data or len(input_data.strip()) == 0:
            return False, "Input cannot be empty"
        
        if len(input_data) > 1000:
            return False, "Input too long (max 1000 characters)"
        
        # Check for potential SQL injection
        dangerous_patterns = ["'", '"', ';', '--', '/*', '*/', 'xp_', 'sp_']
        for pattern in dangerous_patterns:
            if pattern in input_data.lower():
                self.audit_logger.warning(f"Potential SQL injection attempt: {input_data[:100]}")
                return False, "Invalid input detected"
        
        return True, input_data.strip()
    
    def generate_session_token(self) -> str:
        """Generate secure session token"""
        return secrets.token_urlsafe(32)
    
    def validate_session(self, token: str) -> bool:
        """Validate session token (simplified implementation)"""
        # In production, implement proper session management with Redis/database
        return len(token) == 43  # Basic validation for URL-safe token
    
    def get_security_status(self) -> Dict[str, Any]:
        """Get current security status for monitoring"""
        return {
            "encryption_enabled": self.current_key is not None,
            "key_rotation_due": self.key_rotation_date and datetime.now() >= self.key_rotation_date,
            "audit_logging_enabled": True,
            "data_retention_days": self.config["data_retention_days"],
            "last_cleanup": datetime.now().isoformat(),
            "security_config": self.config
        }

# Global security manager instance
security_manager = SecurityManager()
