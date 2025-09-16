from flask import Flask, request, render_template, jsonify, session
import sqlite3
import os
import sys
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from security import security_manager
from hipaa_compliance import hipaa_manager
from error_analysis import error_analysis_manager, ErrorSeverity, ErrorCategory
from chatbot import answer_query
from datetime import datetime
import json
import hashlib
import time

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Required for sessions

# Initialize database and security
def init_app():
    """Initialize database and security components"""
    # Create database table with enhanced schema
    with sqlite3.connect("queries.db") as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS queries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                query TEXT NOT NULL,
                answer TEXT,
                category TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                user_id TEXT,
                session_id TEXT,
                ip_address TEXT,
                user_agent TEXT
            )
        """)
        
        # Create audit log table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                user_id TEXT,
                action TEXT,
                resource TEXT,
                success BOOLEAN,
                ip_address TEXT,
                details TEXT
            )
        """)
    
    # Initialize security manager
    security_manager.rotate_key_if_needed()
    
    # Clean up expired data
    security_manager.check_data_retention()
    
    return security_manager.get_cipher()

# Initialize app components
cipher = init_app()

@app.route("/")
def index():
    """Main page with chat interface"""
    return render_template("index.html")

@app.route("/privacy/consent-page")
def privacy_consent_page():
    """Privacy consent page"""
    return render_template("privacy_consent.html")

@app.route("/privacy/dashboard")
def privacy_dashboard():
    """Privacy dashboard for users to manage their data"""
    return render_template("privacy_dashboard.html")

@app.route("/chat", methods=["POST"])
def chat():
    """Handle chat messages via AJAX with security measures"""
    start_time = time.time()
    
    try:
        # Get client information
        client_ip = request.remote_addr
        user_agent = request.headers.get('User-Agent', 'Unknown')
        
        # Generate or get session ID
        if 'session_id' not in session:
            session['session_id'] = security_manager.generate_session_token()
        
        session_id = session['session_id']
        user_id = session.get('user_id', 'anonymous')
        
        # Get and validate input
        data = request.get_json()
        if not data:
            security_manager.log_access(user_id, "chat_query", "invalid_request", False)
            error_analysis_manager.log_error(
                ValueError("Invalid request format"), 
                "chat_interface", 
                ErrorSeverity.MEDIUM, 
                ErrorCategory.USER_INPUT,
                user_id=user_id,
                session_id=session_id,
                additional_context={'ip_address': client_ip, 'user_agent': user_agent}
            )
            return jsonify({'error': 'Invalid request format'}), 400
        
        query = data.get('question', '').strip()
        
        # Validate input
        is_valid, validation_result = security_manager.validate_input(query)
        if not is_valid:
            security_manager.log_access(user_id, "chat_query", "invalid_input", False)
            error_analysis_manager.log_error(
                ValueError(f"Invalid input: {validation_result}"), 
                "chat_interface", 
                ErrorSeverity.LOW, 
                ErrorCategory.USER_INPUT,
                user_id=user_id,
                session_id=session_id,
                additional_context={'ip_address': client_ip, 'user_agent': user_agent, 'query': query}
            )
            return jsonify({'error': validation_result}), 400
        
        # Check for consent before processing
        if not hipaa_manager.check_consent(user_id):
            security_manager.log_access(user_id, "consent_required", "chat_interface", False)
            return jsonify({
                'error': 'Consent required for data processing',
                'consent_required': True,
                'privacy_policy_url': '/privacy/policy'
            }), 403
        
        # Log access attempt
        security_manager.log_access(user_id, "chat_query", "chat_interface", True)
        
        # Get answer from chatbot with performance monitoring
        try:
            answer = answer_query(query)
            
            # Log performance metrics
            response_time = time.time() - start_time
            error_analysis_manager.log_performance_metric(
                "chat_interface", 
                "response_time", 
                response_time, 
                "seconds",
                {"query_length": len(query), "answer_length": len(answer)}
            )
            
        except Exception as e:
            # Log chatbot error
            error_analysis_manager.log_error(
                e, 
                "chatbot", 
                ErrorSeverity.HIGH, 
                ErrorCategory.BUSINESS_LOGIC,
                user_id=user_id,
                session_id=session_id,
                additional_context={'ip_address': client_ip, 'user_agent': user_agent, 'query': query}
            )
            raise e
        
        # Encrypt sensitive data
        try:
            if cipher:
                encrypted_query = cipher.encrypt(query.encode()).decode()
                encrypted_answer = cipher.encrypt(answer.encode()).decode()
            else:
                # Fallback if encryption fails
                encrypted_query = query
                encrypted_answer = answer
        except Exception as e:
            error_analysis_manager.log_error(
                e, 
                "encryption", 
                ErrorSeverity.HIGH, 
                ErrorCategory.SECURITY,
                user_id=user_id,
                session_id=session_id,
                additional_context={'ip_address': client_ip, 'user_agent': user_agent}
            )
            # Fallback to plain text
            encrypted_query = query
            encrypted_answer = answer
        
        # Log query to database with security metadata
        try:
            with sqlite3.connect("queries.db") as conn:
                conn.execute("""
                    INSERT INTO queries (query, answer, timestamp, user_id, session_id, ip_address, user_agent) 
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    encrypted_query,
                    encrypted_answer,
                    datetime.now().isoformat(),
                    user_id,
                    session_id,
                    client_ip,
                    user_agent
                ))
        except Exception as e:
            error_analysis_manager.log_error(
                e, 
                "database", 
                ErrorSeverity.HIGH, 
                ErrorCategory.DATA,
                user_id=user_id,
                session_id=session_id,
                additional_context={'ip_address': client_ip, 'user_agent': user_agent}
            )
            # Continue execution even if database logging fails
        
        # Log successful query
        security_manager.log_access(user_id, "query_processed", "chat_interface", True)
        
        return jsonify({
            'question': query,
            'answer': answer,
            'timestamp': datetime.now().isoformat(),
            'session_id': session_id,
            'response_time': round(response_time, 3)
        })
        
    except Exception as e:
        # Log error with comprehensive context
        user_id = session.get('user_id', 'anonymous')
        session_id = session.get('session_id', 'unknown')
        
        error_analysis_manager.log_error(
            e, 
            "chat_interface", 
            ErrorSeverity.HIGH, 
            ErrorCategory.SYSTEM,
            user_id=user_id,
            session_id=session_id,
            request_data=data if 'data' in locals() else None,
            additional_context={'ip_address': client_ip, 'user_agent': user_agent}
        )
        
        security_manager.log_access(user_id, "chat_error", "chat_interface", False)
        return jsonify({'error': f'Server error: {str(e)}'}), 500

@app.route("/analytics")
def analytics():
    """Analytics dashboard - returns JSON data for the dashboard"""
    try:
        # Import and run analytics
        from analytics import AnalyticsEngine
        analytics_engine = AnalyticsEngine()
        df = analytics_engine.load_data()
        
        if df is None:
            return jsonify({
                "insights": {
                    "total_queries": 0,
                    "unique_users": "N/A",
                    "date_range": {
                        "start": "No data",
                        "end": "No data"
                    },
                    "categories": {},
                    "recent_queries": [],
                    "hourly_distribution": {},
                    "daily_distribution": {}
                },
                "status": "success"
            })
        
        insights = analytics_engine.generate_insights(df)
        analytics_engine.create_visualizations(df)
        
        return jsonify({
            "insights": insights,
            "status": "success"
        })
        
    except Exception as e:
        print(f"❌ Analytics error: {str(e)}")
        # Return safe fallback data instead of error
        return jsonify({
            "insights": {
                "total_queries": 0,
                "unique_users": "N/A",
                "date_range": {
                    "start": "Error",
                    "end": "Error"
                },
                "categories": {},
                "recent_queries": [],
                "hourly_distribution": {},
                "daily_distribution": {}
            },
            "status": "error",
            "error_message": str(e)
        })

@app.route("/analytics/dashboard")
def analytics_dashboard():
    """Serve the analytics dashboard HTML page"""
    return render_template("analytics.html")

@app.route("/security/status")
def security_status():
    """Get current security status (admin only)"""
    try:
        status = security_manager.get_security_status()
        return jsonify(status)
    except Exception as e:
        return jsonify({'error': f'Security status error: {str(e)}'}), 500

@app.route("/security/audit")
def security_audit():
    """Get recent audit logs (admin only)"""
    try:
        with sqlite3.connect("queries.db") as conn:
            cursor = conn.execute("""
                SELECT timestamp, user_id, action, resource, success, ip_address, details
                FROM audit_log 
                ORDER BY timestamp DESC 
                LIMIT 100
            """)
            logs = cursor.fetchall()
        
        audit_data = []
        for log in logs:
            audit_data.append({
                "timestamp": log[0],
                "user_id": log[1],
                "action": log[2],
                "resource": log[3],
                "success": bool(log[4]),
                "ip_address": log[5],
                "details": log[6]
            })
        
        return jsonify({"audit_logs": audit_data})
    except Exception as e:
        return jsonify({'error': f'Audit log error: {str(e)}'}), 500

# HIPAA Compliance Routes
@app.route("/privacy/policy")
def privacy_policy():
    """Get privacy policy"""
    try:
        policy = hipaa_manager.get_privacy_policy()
        return jsonify(policy)
    except Exception as e:
        return jsonify({'error': f'Privacy policy error: {str(e)}'}), 500

@app.route("/test-consent")
def test_consent():
    """Test consent endpoint"""
    return jsonify({"status": "test_consent_working"})

@app.route("/privacy/consent", methods=["GET"])
def get_consent_status():
    """Get current consent status for user"""
    try:
        user_id = session.get('user_id', 'anonymous')
        consent_given = hipaa_manager.check_consent(user_id)
        
        return jsonify({
            "user_id": user_id,
            "consent_given": consent_given,
            "consent_type": "data_processing",
            "timestamp": datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({'error': f'Consent status error: {str(e)}'}), 500

@app.route("/privacy/consent", methods=["POST"])
def request_consent():
    """Request user consent for data processing"""
    try:
        user_id = session.get('user_id', 'anonymous')
        session_id = session.get('session_id', 'unknown')
        consent_type = request.json.get('consent_type', 'data_processing')
        
        consent_data = hipaa_manager.request_consent(
            user_id=user_id,
            session_id=session_id,
            consent_type=consent_type,
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent')
        )
        
        return jsonify(consent_data)
    except Exception as e:
        return jsonify({'error': f'Consent request error: {str(e)}'}), 500

@app.route("/privacy/consent", methods=["PUT"])
def record_consent():
    """Record user consent decision"""
    try:
        user_id = session.get('user_id', 'anonymous')
        session_id = session.get('session_id', 'unknown')
        data = request.get_json()
        
        consent_given = data.get('consent_given', False)
        consent_type = data.get('consent_type', 'data_processing')
        purposes = data.get('purposes', ['service_provision', 'analytics'])
        
        success = hipaa_manager.record_consent(
            user_id=user_id,
            session_id=session_id,
            consent_type=consent_type,
            consent_given=consent_given,
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent'),
            purposes=purposes
        )
        
        if success:
            return jsonify({"success": True, "message": "Consent recorded successfully"})
        else:
            return jsonify({"success": False, "error": "Failed to record consent"}), 500
            
    except Exception as e:
        return jsonify({'error': f'Consent recording error: {str(e)}'}), 500

@app.route("/privacy/consent", methods=["DELETE"])
def withdraw_consent():
    """Withdraw user consent"""
    try:
        user_id = session.get('user_id', 'anonymous')
        data = request.get_json()
        reason = data.get('reason', 'User request')
        consent_type = data.get('consent_type', 'data_processing')
        
        success = hipaa_manager.withdraw_consent(
            user_id=user_id,
            consent_type=consent_type,
            reason=reason
        )
        
        if success:
            return jsonify({"success": True, "message": "Consent withdrawn successfully"})
        else:
            return jsonify({"success": False, "error": "Failed to withdraw consent"}), 500
            
    except Exception as e:
        return jsonify({'error': f'Consent withdrawal error: {str(e)}'}), 500

@app.route("/privacy/export")
def export_user_data():
    """Export user data for portability"""
    try:
        user_id = session.get('user_id', 'anonymous')
        
        # Check if user has consent
        if not hipaa_manager.check_consent(user_id):
            return jsonify({'error': 'Consent required for data export'}), 403
        
        export_data = hipaa_manager.export_user_data(user_id)
        return jsonify(export_data)
        
    except Exception as e:
        return jsonify({'error': f'Data export error: {str(e)}'}), 500

@app.route("/privacy/delete", methods=["POST"])
def delete_user_data():
    """Delete user data (Right to be Forgotten)"""
    try:
        user_id = session.get('user_id', 'anonymous')
        data = request.get_json()
        deletion_type = data.get('deletion_type', 'full')
        reason = data.get('reason', 'User request')
        
        deletion_result = hipaa_manager.delete_user_data(
            user_id=user_id,
            deletion_type=deletion_type,
            reason=reason
        )
        
        return jsonify(deletion_result)
        
    except Exception as e:
        return jsonify({'error': f'Data deletion error: {str(e)}'}), 500

@app.route("/privacy/anonymize", methods=["POST"])
def anonymize_user_data():
    """Anonymize user data while preserving analytics"""
    try:
        user_id = session.get('user_id', 'anonymous')
        
        success = hipaa_manager.anonymize_data(user_id)
        
        if success:
            return jsonify({"success": True, "message": "Data anonymized successfully"})
        else:
            return jsonify({"success": False, "error": "Failed to anonymize data"}), 500
            
    except Exception as e:
        return jsonify({'error': f'Data anonymization error: {str(e)}'}), 500

@app.route("/privacy/compliance")
def compliance_status():
    """Get HIPAA compliance status (admin only)"""
    try:
        status = hipaa_manager.get_compliance_status()
        return jsonify(status)
    except Exception as e:
        return jsonify({'error': f'Compliance status error: {str(e)}'}), 500

# Error Analysis Routes
@app.route("/error-analysis")
def error_analysis():
    """Get error analysis data for dashboard"""
    try:
        hours = int(request.args.get('hours', 24))
        severity = request.args.get('severity', '')
        component = request.args.get('component', '')
        
        # Get error summary
        error_summary = error_analysis_manager.get_error_summary(hours)
        
        # Get active alerts
        alerts = error_analysis_manager.get_active_alerts()
        
        # Get performance metrics
        performance_metrics = error_analysis_manager.get_performance_metrics(component, hours)
        
        return jsonify({
            "summary": error_summary.get("summary", {}),
            "recent_errors": error_summary.get("recent_errors", []),
            "top_patterns": error_summary.get("top_patterns", []),
            "alerts": alerts,
            "performance_metrics": performance_metrics.get("metrics", []),
            "time_range": error_summary.get("time_range", {}),
            "status": "success"
        })
        
    except Exception as e:
        # Log the error
        error_analysis_manager.log_error(
            e, "error_analysis", 
            ErrorSeverity.HIGH, 
            ErrorCategory.SYSTEM
        )
        return jsonify({'error': f'Error analysis error: {str(e)}'}), 500

@app.route("/error-analysis/dashboard")
def error_analysis_dashboard():
    """Serve the error analysis dashboard HTML page"""
    return render_template("error_dashboard.html")

@app.route("/error-analysis/acknowledge/<int:alert_id>", methods=["POST"])
def acknowledge_alert(alert_id):
    """Acknowledge an alert"""
    try:
        success = error_analysis_manager.acknowledge_alert(alert_id, "admin")
        if success:
            return jsonify({"success": True, "message": "Alert acknowledged successfully"})
        else:
            return jsonify({"success": False, "error": "Failed to acknowledge alert"}), 500
    except Exception as e:
        error_analysis_manager.log_error(
            e, "acknowledge_alert", 
            ErrorSeverity.MEDIUM, 
            ErrorCategory.SYSTEM
        )
        return jsonify({'error': f'Alert acknowledgment error: {str(e)}'}), 500

@app.route("/error-analysis/resolve/<error_id>", methods=["POST"])
def resolve_error(error_id):
    """Resolve an error"""
    try:
        data = request.get_json()
        resolution_notes = data.get('resolution_notes', 'Resolved by admin')
        resolved_by = data.get('resolved_by', 'admin')
        
        success = error_analysis_manager.resolve_error(error_id, resolution_notes, resolved_by)
        if success:
            return jsonify({"success": True, "message": "Error resolved successfully"})
        else:
            return jsonify({"success": False, "error": "Failed to resolve error"}), 500
    except Exception as e:
        error_analysis_manager.log_error(
            e, "resolve_error", 
            ErrorSeverity.MEDIUM, 
            ErrorCategory.SYSTEM
        )
        return jsonify({'error': f'Error resolution error: {str(e)}'}), 500

if __name__ == "__main__":
    print("🚀 Starting Insurance Chatbot Web App...")
    print("🔒 Security features enabled")
    print("📊 Visit http://localhost:5002 for the web interface")
    print("📈 Visit http://localhost:5002/analytics for query analytics")
    print("🛡️  Visit http://localhost:5002/security/status for security status")
    print("⏳ Starting server...")
    app.run(debug=False, host="127.0.0.1", port=5002)  # Disabled debug for security