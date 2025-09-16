import os
import json
import sqlite3
import traceback
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from enum import Enum
import hashlib
import uuid

class ErrorSeverity(Enum):
    """Error severity levels"""
    CRITICAL = "critical"      # System down, data loss, security breach
    HIGH = "high"             # Major functionality broken, performance issues
    MEDIUM = "medium"         # Minor functionality issues, user experience problems
    LOW = "low"              # Cosmetic issues, non-critical warnings
    INFO = "info"            # Informational messages, debugging info

class ErrorCategory(Enum):
    """Error categories for better organization"""
    SECURITY = "security"           # Authentication, authorization, data breaches
    PERFORMANCE = "performance"     # Slow responses, memory issues, timeouts
    DATA = "data"                  # Database errors, data corruption, validation
    NETWORK = "network"            # Connection issues, API failures
    USER_INPUT = "user_input"      # Invalid input, malformed requests
    SYSTEM = "system"              # Internal errors, configuration issues
    EXTERNAL = "external"          # Third-party service failures
    BUSINESS_LOGIC = "business_logic"  # Chatbot logic, ML model errors
    UNKNOWN = "unknown"            # Unclassified errors

class ErrorAnalysisManager:
    """Comprehensive error analysis and monitoring system"""
    
    def __init__(self, db_path: str = "error_analysis.db"):
        """Initialize error analysis manager"""
        self.db_path = db_path
        self.logger = self._setup_logger()
        self._init_database()
        
        # Error tracking configuration
        self.alert_thresholds = {
            ErrorSeverity.CRITICAL: 1,    # Alert immediately
            ErrorSeverity.HIGH: 5,        # Alert after 5 occurrences
            ErrorSeverity.MEDIUM: 20,     # Alert after 20 occurrences
            ErrorSeverity.LOW: 100,       # Alert after 100 occurrences
        }
        
        # Performance monitoring
        self.performance_metrics = {
            "response_times": [],
            "memory_usage": [],
            "error_rates": {},
            "success_rates": {}
        }
    
    def _setup_logger(self) -> logging.Logger:
        """Setup error analysis logger"""
        logger = logging.getLogger('error_analysis')
        logger.setLevel(logging.INFO)
        
        # Create logs directory if it doesn't exist
        os.makedirs("logs", exist_ok=True)
        
        # File handler for error logs
        file_handler = logging.FileHandler('logs/error_analysis.log')
        file_handler.setLevel(logging.INFO)
        
        # Console handler for critical errors
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.ERROR)
        
        # Formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)
        
        logger.addHandler(file_handler)
        logger.addHandler(console_handler)
        
        return logger
    
    def _init_database(self):
        """Initialize error analysis database"""
        with sqlite3.connect(self.db_path) as conn:
            # Main errors table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS errors (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    error_id TEXT UNIQUE NOT NULL,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    severity TEXT NOT NULL,
                    category TEXT NOT NULL,
                    component TEXT NOT NULL,
                    error_type TEXT NOT NULL,
                    error_message TEXT NOT NULL,
                    stack_trace TEXT,
                    user_id TEXT,
                    session_id TEXT,
                    ip_address TEXT,
                    user_agent TEXT,
                    request_data TEXT,
                    response_data TEXT,
                    resolved BOOLEAN DEFAULT FALSE,
                    resolution_notes TEXT,
                    resolved_at DATETIME,
                    resolved_by TEXT
                )
            """)
            
            # Error patterns table for aggregation
            conn.execute("""
                CREATE TABLE IF NOT EXISTS error_patterns (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    pattern_hash TEXT UNIQUE NOT NULL,
                    error_type TEXT NOT NULL,
                    component TEXT NOT NULL,
                    first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                    occurrence_count INTEGER DEFAULT 1,
                    severity TEXT NOT NULL,
                    category TEXT NOT NULL,
                    sample_message TEXT,
                    sample_stack_trace TEXT
                )
            """)
            
            # Performance metrics table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS performance_metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    component TEXT NOT NULL,
                    metric_name TEXT NOT NULL,
                    metric_value REAL NOT NULL,
                    metric_unit TEXT,
                    additional_data TEXT
                )
            """)
            
            # Error alerts table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS error_alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    alert_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    message TEXT NOT NULL,
                    error_count INTEGER,
                    component TEXT,
                    acknowledged BOOLEAN DEFAULT FALSE,
                    acknowledged_at DATETIME,
                    acknowledged_by TEXT
                )
            """)
    
    def log_error(self, 
                  error: Exception,
                  component: str,
                  severity: ErrorSeverity = ErrorSeverity.MEDIUM,
                  category: ErrorCategory = ErrorCategory.UNKNOWN,
                  user_id: str = None,
                  session_id: str = None,
                  request_data: Dict = None,
                  response_data: Dict = None,
                  additional_context: Dict = None) -> str:
        """Log an error with comprehensive context"""
        
        # Generate unique error ID
        error_id = str(uuid.uuid4())
        
        # Extract error information
        error_type = type(error).__name__
        error_message = str(error)
        stack_trace = traceback.format_exc()
        
        # Get client information
        ip_address = additional_context.get('ip_address', 'unknown') if additional_context else 'unknown'
        user_agent = additional_context.get('user_agent', 'unknown') if additional_context else 'unknown'
        
        # Serialize request/response data
        request_json = json.dumps(request_data) if request_data else None
        response_json = json.dumps(response_data) if response_data else None
        
        try:
            # Store error in database
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT INTO errors (
                        error_id, severity, category, component, error_type,
                        error_message, stack_trace, user_id, session_id,
                        ip_address, user_agent, request_data, response_data
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    error_id, severity.value, category.value, component,
                    error_type, error_message, stack_trace, user_id, session_id,
                    ip_address, user_agent, request_json, response_json
                ))
            
            # Update error patterns
            self._update_error_patterns(error_type, component, severity, category, error_message, stack_trace)
            
            # Check for alerts
            self._check_alert_conditions(severity, component)
            
            # Log to file
            self.logger.error(f"Error {error_id}: {error_type} in {component} - {error_message}")
            
            return error_id
            
        except Exception as e:
            # Fallback logging if database fails
            self.logger.critical(f"Failed to log error {error_id}: {str(e)}")
            return error_id
    
    def _update_error_patterns(self, error_type: str, component: str, severity: ErrorSeverity, 
                             category: ErrorCategory, error_message: str, stack_trace: str):
        """Update error pattern aggregation"""
        # Create pattern hash for similar errors
        pattern_data = f"{error_type}:{component}:{error_message[:100]}"
        pattern_hash = hashlib.md5(pattern_data.encode()).hexdigest()
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                # Check if pattern exists
                cursor = conn.execute("""
                    SELECT occurrence_count FROM error_patterns 
                    WHERE pattern_hash = ?
                """, (pattern_hash,))
                
                result = cursor.fetchone()
                
                if result:
                    # Update existing pattern
                    new_count = result[0] + 1
                    conn.execute("""
                        UPDATE error_patterns 
                        SET occurrence_count = ?, last_seen = CURRENT_TIMESTAMP
                        WHERE pattern_hash = ?
                    """, (new_count, pattern_hash))
                else:
                    # Create new pattern
                    conn.execute("""
                        INSERT INTO error_patterns (
                            pattern_hash, error_type, component, severity, category,
                            sample_message, sample_stack_trace
                        ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """, (
                        pattern_hash, error_type, component, severity.value,
                        category.value, error_message[:500], stack_trace[:1000]
                    ))
        except Exception as e:
            self.logger.error(f"Failed to update error patterns: {str(e)}")
    
    def _check_alert_conditions(self, severity: ErrorSeverity, component: str):
        """Check if alert conditions are met"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                # Count recent errors of this severity
                since_time = datetime.now() - timedelta(hours=1)
                cursor = conn.execute("""
                    SELECT COUNT(*) FROM errors 
                    WHERE severity = ? AND timestamp > ?
                """, (severity.value, since_time.isoformat()))
                
                error_count = cursor.fetchone()[0]
                threshold = self.alert_thresholds.get(severity, 100)
                
                if error_count >= threshold:
                    # Create alert
                    alert_message = f"High error rate detected: {error_count} {severity.value} errors in the last hour"
                    conn.execute("""
                        INSERT INTO error_alerts (alert_type, severity, message, error_count, component)
                        VALUES (?, ?, ?, ?, ?)
                    """, ("high_error_rate", severity.value, alert_message, error_count, component))
                    
                    # Log critical alert
                    self.logger.critical(f"ALERT: {alert_message}")
                    
        except Exception as e:
            self.logger.error(f"Failed to check alert conditions: {str(e)}")
    
    def log_performance_metric(self, component: str, metric_name: str, 
                             metric_value: float, metric_unit: str = None, 
                             additional_data: Dict = None):
        """Log performance metrics"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                additional_json = json.dumps(additional_data) if additional_data else None
                conn.execute("""
                    INSERT INTO performance_metrics (component, metric_name, metric_value, metric_unit, additional_data)
                    VALUES (?, ?, ?, ?, ?)
                """, (component, metric_name, metric_value, metric_unit, additional_json))
                
        except Exception as e:
            self.logger.error(f"Failed to log performance metric: {str(e)}")
    
    def get_error_summary(self, hours: int = 24) -> Dict[str, Any]:
        """Get error summary for the last N hours"""
        try:
            since_time = datetime.now() - timedelta(hours=hours)
            
            with sqlite3.connect(self.db_path) as conn:
                # Error counts by severity
                cursor = conn.execute("""
                    SELECT severity, COUNT(*) as count
                    FROM errors 
                    WHERE timestamp > ?
                    GROUP BY severity
                """, (since_time.isoformat(),))
                severity_counts = dict(cursor.fetchall())
                
                # Error counts by category
                cursor = conn.execute("""
                    SELECT category, COUNT(*) as count
                    FROM errors 
                    WHERE timestamp > ?
                    GROUP BY category
                """, (since_time.isoformat(),))
                category_counts = dict(cursor.fetchall())
                
                # Error counts by component
                cursor = conn.execute("""
                    SELECT component, COUNT(*) as count
                    FROM errors 
                    WHERE timestamp > ?
                    GROUP BY component
                """, (since_time.isoformat(),))
                component_counts = dict(cursor.fetchall())
                
                # Recent errors
                cursor = conn.execute("""
                    SELECT error_id, timestamp, severity, category, component, error_type, error_message
                    FROM errors 
                    WHERE timestamp > ?
                    ORDER BY timestamp DESC
                    LIMIT 50
                """, (since_time.isoformat(),))
                recent_errors = [
                    {
                        "error_id": row[0],
                        "timestamp": row[1],
                        "severity": row[2],
                        "category": row[3],
                        "component": row[4],
                        "error_type": row[5],
                        "error_message": row[6]
                    }
                    for row in cursor.fetchall()
                ]
                
                # Top error patterns
                cursor = conn.execute("""
                    SELECT error_type, component, occurrence_count, last_seen
                    FROM error_patterns 
                    ORDER BY occurrence_count DESC
                    LIMIT 10
                """)
                top_patterns = [
                    {
                        "error_type": row[0],
                        "component": row[1],
                        "occurrence_count": row[2],
                        "last_seen": row[3]
                    }
                    for row in cursor.fetchall()
                ]
                
                return {
                    "summary": {
                        "total_errors": sum(severity_counts.values()),
                        "severity_breakdown": severity_counts,
                        "category_breakdown": category_counts,
                        "component_breakdown": component_counts
                    },
                    "recent_errors": recent_errors,
                    "top_patterns": top_patterns,
                    "time_range": {
                        "start": since_time.isoformat(),
                        "end": datetime.now().isoformat(),
                        "hours": hours
                    }
                }
                
        except Exception as e:
            self.logger.error(f"Failed to get error summary: {str(e)}")
            return {"error": str(e)}
    
    def get_performance_metrics(self, component: str = None, hours: int = 24) -> Dict[str, Any]:
        """Get performance metrics for analysis"""
        try:
            since_time = datetime.now() - timedelta(hours=hours)
            
            with sqlite3.connect(self.db_path) as conn:
                query = """
                    SELECT component, metric_name, AVG(metric_value) as avg_value, 
                           MIN(metric_value) as min_value, MAX(metric_value) as max_value,
                           COUNT(*) as sample_count
                    FROM performance_metrics 
                    WHERE timestamp > ?
                """
                params = [since_time.isoformat()]
                
                if component:
                    query += " AND component = ?"
                    params.append(component)
                
                query += " GROUP BY component, metric_name ORDER BY component, metric_name"
                
                cursor = conn.execute(query, params)
                metrics = [
                    {
                        "component": row[0],
                        "metric_name": row[1],
                        "avg_value": row[2],
                        "min_value": row[3],
                        "max_value": row[4],
                        "sample_count": row[5]
                    }
                    for row in cursor.fetchall()
                ]
                
                return {
                    "metrics": metrics,
                    "time_range": {
                        "start": since_time.isoformat(),
                        "end": datetime.now().isoformat(),
                        "hours": hours
                    }
                }
                
        except Exception as e:
            self.logger.error(f"Failed to get performance metrics: {str(e)}")
            return {"error": str(e)}
    
    def resolve_error(self, error_id: str, resolution_notes: str, resolved_by: str = "system"):
        """Mark an error as resolved"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    UPDATE errors 
                    SET resolved = TRUE, resolution_notes = ?, resolved_at = CURRENT_TIMESTAMP, resolved_by = ?
                    WHERE error_id = ?
                """, (resolution_notes, resolved_by, error_id))
                
            self.logger.info(f"Error {error_id} resolved by {resolved_by}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to resolve error {error_id}: {str(e)}")
            return False
    
    def get_active_alerts(self) -> List[Dict[str, Any]]:
        """Get active (unacknowledged) alerts"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute("""
                    SELECT id, timestamp, alert_type, severity, message, error_count, component
                    FROM error_alerts 
                    WHERE acknowledged = FALSE
                    ORDER BY timestamp DESC
                """)
                
                return [
                    {
                        "id": row[0],
                        "timestamp": row[1],
                        "alert_type": row[2],
                        "severity": row[3],
                        "message": row[4],
                        "error_count": row[5],
                        "component": row[6]
                    }
                    for row in cursor.fetchall()
                ]
                
        except Exception as e:
            self.logger.error(f"Failed to get active alerts: {str(e)}")
            return []
    
    def acknowledge_alert(self, alert_id: int, acknowledged_by: str = "admin"):
        """Acknowledge an alert"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    UPDATE error_alerts 
                    SET acknowledged = TRUE, acknowledged_at = CURRENT_TIMESTAMP, acknowledged_by = ?
                    WHERE id = ?
                """, (acknowledged_by, alert_id))
                
            self.logger.info(f"Alert {alert_id} acknowledged by {acknowledged_by}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to acknowledge alert {alert_id}: {str(e)}")
            return False

# Global error analysis manager instance
error_analysis_manager = ErrorAnalysisManager()

# Convenience functions for easy integration
def log_error(error: Exception, component: str, **kwargs) -> str:
    """Convenience function to log errors"""
    return error_analysis_manager.log_error(error, component, **kwargs)

def log_performance(component: str, metric_name: str, value: float, **kwargs):
    """Convenience function to log performance metrics"""
    error_analysis_manager.log_performance_metric(component, metric_name, value, **kwargs)

def get_error_summary(hours: int = 24) -> Dict[str, Any]:
    """Convenience function to get error summary"""
    return error_analysis_manager.get_error_summary(hours)

def get_performance_metrics(component: str = None, hours: int = 24) -> Dict[str, Any]:
    """Convenience function to get performance metrics"""
    return error_analysis_manager.get_performance_metrics(component, hours)
