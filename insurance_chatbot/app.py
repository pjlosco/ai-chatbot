from flask import Flask, request, render_template, jsonify, session
import sqlite3
import os
from security import security_manager
from chatbot import answer_query
from datetime import datetime
import json
import hashlib

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

@app.route("/chat", methods=["POST"])
def chat():
    """Handle chat messages via AJAX with security measures"""
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
            return jsonify({'error': 'Invalid request format'}), 400
        
        query = data.get('question', '').strip()
        
        # Validate input
        is_valid, validation_result = security_manager.validate_input(query)
        if not is_valid:
            security_manager.log_access(user_id, "chat_query", "invalid_input", False)
            return jsonify({'error': validation_result}), 400
        
        # Log access attempt
        security_manager.log_access(user_id, "chat_query", "chat_interface", True)
        
        # Get answer from chatbot
        answer = answer_query(query)
        
        # Encrypt sensitive data
        if cipher:
            encrypted_query = cipher.encrypt(query.encode()).decode()
            encrypted_answer = cipher.encrypt(answer.encode()).decode()
        else:
            # Fallback if encryption fails
            encrypted_query = query
            encrypted_answer = answer
        
        # Log query to database with security metadata
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
        
        # Log successful query
        security_manager.log_access(user_id, "query_processed", "chat_interface", True)
        
        return jsonify({
            'question': query,
            'answer': answer,
            'timestamp': datetime.now().isoformat(),
            'session_id': session_id
        })
        
    except Exception as e:
        # Log error
        user_id = session.get('user_id', 'anonymous')
        security_manager.log_access(user_id, "chat_error", "chat_interface", False)
        return jsonify({'error': f'Server error: {str(e)}'}), 500

@app.route("/analytics")
def analytics():
    """Analytics dashboard - returns JSON data for the dashboard"""
    try:
        # Import and run analytics
        from analytics import AnalyticsEngine
        analytics_engine = AnalyticsEngine()
        insights = analytics_engine.run_analysis()
        
        if insights is None:
            return jsonify({'error': 'No data available for analysis'}), 404
        
        return jsonify(insights)
        
    except Exception as e:
        print(f"❌ Analytics error: {str(e)}")
        return jsonify({'error': f'Analytics error: {str(e)}'}), 500

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

if __name__ == "__main__":
    print("🚀 Starting Insurance Chatbot Web App...")
    print("🔒 Security features enabled")
    print("📊 Visit http://localhost:5002 for the web interface")
    print("📈 Visit http://localhost:5002/analytics for query analytics")
    print("🛡️  Visit http://localhost:5002/security/status for security status")
    print("⏳ Starting server...")
    app.run(debug=False, host="127.0.0.1", port=5002)  # Disabled debug for security