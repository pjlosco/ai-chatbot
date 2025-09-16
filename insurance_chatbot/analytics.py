import sqlite3
import pandas as pd
import matplotlib
# Set backend before importing pyplot to avoid GUI threading issues
matplotlib.use('Agg')  # Use non-GUI backend for web deployment
import matplotlib.pyplot as plt
import os
from datetime import datetime, timedelta
from security import security_manager
import joblib

class AnalyticsEngine:
    def __init__(self):
        """Initialize analytics with secure key management"""
        # Use security manager for encryption
        self.cipher = security_manager.get_cipher()
        if not self.cipher:
            print("❌ No encryption key available. Security manager not initialized.")
        
        # Load ML classifier for better categorization
        self.classifier = None
        self.vectorizer = None
        if os.path.exists("models/query_classifier.pkl"):
            try:
                self.classifier = joblib.load("models/query_classifier.pkl")
                self.vectorizer = joblib.load("models/vectorizer.pkl")
                print("✅ ML Classifier loaded for analytics")
            except Exception as e:
                print(f"⚠️  Could not load classifier: {e}")
    
    def load_data(self):
        """Load and decrypt query data from database with security measures"""
        if not self.cipher:
            return None
            
        try:
            with sqlite3.connect("queries.db") as conn:
                df = pd.read_sql_query("""
                    SELECT query, answer, timestamp, user_id, session_id, ip_address, user_agent
                    FROM queries 
                    ORDER BY timestamp DESC
                """, conn)
            
            if df.empty:
                print("📊 No query data found in database")
                return pd.DataFrame()
            
            # Decrypt data securely
            def safe_decrypt(encrypted_text):
                try:
                    if isinstance(encrypted_text, str) and encrypted_text.startswith('gAAAAAB'):
                        # This looks like encrypted data
                        return self.cipher.decrypt(encrypted_text.encode()).decode()
                    else:
                        # This might be plain text (for migration)
                        return encrypted_text
                except Exception as e:
                    # Only print warning once, not for every record
                    if not hasattr(safe_decrypt, 'warning_printed'):
                        print(f"⚠️  Some data may not be encrypted (migration in progress)")
                        safe_decrypt.warning_printed = True
                    return "[DECRYPTION_ERROR]"
            
            df["query"] = df["query"].apply(safe_decrypt)
            df["answer"] = df["answer"].apply(safe_decrypt)
            df["timestamp"] = pd.to_datetime(df["timestamp"])
            
            # Anonymize sensitive data for analytics
            df["query"] = df["query"].apply(security_manager.anonymize_data)
            df["answer"] = df["answer"].apply(security_manager.anonymize_data)
            
            print(f"✅ Loaded {len(df)} queries from database (anonymized for analytics)")
            return df
            
        except Exception as e:
            print(f"❌ Error loading data: {e}")
            return None
    
    def categorize_queries(self, df):
        """Categorize queries using ML classifier"""
        if df.empty:
            return df
            
        # Always ensure category column exists
        if "category" not in df.columns:
            df["category"] = "Unknown"
        
        if not self.classifier or not self.vectorizer:
            # Fallback to simple keyword matching
            df["category"] = df["query"].apply(self._simple_categorize)
            return df
        
        try:
            # Use ML classifier
            query_vec = self.vectorizer.transform(df["query"])
            df["category"] = self.classifier.predict(query_vec)
            df["confidence"] = self.classifier.predict_proba(query_vec).max(axis=1)
            return df
        except Exception as e:
            print(f"⚠️  ML categorization failed: {e}")
            df["category"] = df["query"].apply(self._simple_categorize)
            return df
    
    def _simple_categorize(self, query):
        """Simple keyword-based categorization fallback"""
        query_lower = query.lower()
        if any(word in query_lower for word in ["hmo", "ppo", "epo", "plan", "deductible", "copay", "premium"]):
            return "Plan Type"
        elif any(word in query_lower for word in ["enroll", "sign up", "deadline", "open enrollment"]):
            return "Enrollment"
        else:
            return "Other"
    
    def generate_insights(self, df):
        """Generate comprehensive analytics insights"""
        if df.empty:
            return {
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
            }
        
        # Ensure category column exists
        if "category" not in df.columns:
            df["category"] = "Unknown"
        
        try:
            # Convert recent queries to JSON-serializable format
            recent_queries = []
            for _, row in df.head(10).iterrows():
                recent_queries.append({
                    "query": str(row["query"]),
                    "answer": str(row["answer"]),
                    "timestamp": row["timestamp"].strftime("%Y-%m-%d %H:%M:%S"),
                    "category": str(row.get("category", "Unknown"))
                })
            
            # Convert hourly distribution to JSON-serializable format
            hourly_dist = df.groupby(df["timestamp"].dt.hour).size()
            hourly_dict = {str(hour): int(count) for hour, count in hourly_dist.items()}
            
            # Convert daily distribution to JSON-serializable format
            daily_dist = df.groupby(df["timestamp"].dt.date).size()
            daily_dict = {str(date): int(count) for date, count in daily_dist.items()}
            
            # Safe category counting
            category_counts = df["category"].value_counts() if not df["category"].empty else {}
            
            insights = {
                "total_queries": int(len(df)),
                "unique_users": "N/A",  # We don't track users in this simple version
                "date_range": {
                    "start": df["timestamp"].min().strftime("%Y-%m-%d %H:%M"),
                    "end": df["timestamp"].max().strftime("%Y-%m-%d %H:%M")
                },
                "categories": {str(k): int(v) for k, v in category_counts.items()},
                "recent_queries": recent_queries,
                "hourly_distribution": hourly_dict,
                "daily_distribution": daily_dict
            }
            
            return insights
            
        except Exception as e:
            print(f"❌ Error in generate_insights: {e}")
            # Return safe fallback data
            return {
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
            }
    
    def create_visualizations(self, df):
        """Create analytics visualizations"""
        if df.empty:
            print("⚠️  No data available for visualization")
            return
        
        try:
            # Ensure static directory exists
            os.makedirs("static", exist_ok=True)
            
            # Ensure category column exists
            if "category" not in df.columns:
                df["category"] = "Unknown"
            
            # Set up the plotting style
            plt.style.use('default')
            fig, axes = plt.subplots(2, 2, figsize=(15, 10))
            fig.suptitle('Insurance Chatbot Analytics Dashboard', fontsize=16, fontweight='bold')
            
            # 1. Category Distribution
            if "category" in df.columns and not df["category"].empty:
                category_counts = df["category"].value_counts()
                if not category_counts.empty:
                    axes[0, 0].pie(category_counts.values, labels=category_counts.index, autopct='%1.1f%%')
                    axes[0, 0].set_title('Query Categories')
                else:
                    axes[0, 0].text(0.5, 0.5, 'No category data', ha='center', va='center')
                    axes[0, 0].set_title('Query Categories')
            else:
                axes[0, 0].text(0.5, 0.5, 'No category data', ha='center', va='center')
                axes[0, 0].set_title('Query Categories')
            
            # 2. Hourly Distribution
            if "timestamp" in df.columns and not df["timestamp"].empty:
                hourly_counts = df.groupby(df["timestamp"].dt.hour).size()
                if not hourly_counts.empty:
                    axes[0, 1].bar(hourly_counts.index, hourly_counts.values)
                    axes[0, 1].set_title('Queries by Hour of Day')
                    axes[0, 1].set_xlabel('Hour')
                    axes[0, 1].set_ylabel('Number of Queries')
                else:
                    axes[0, 1].text(0.5, 0.5, 'No hourly data', ha='center', va='center')
                    axes[0, 1].set_title('Queries by Hour of Day')
            else:
                axes[0, 1].text(0.5, 0.5, 'No timestamp data', ha='center', va='center')
                axes[0, 1].set_title('Queries by Hour of Day')
            
            # 3. Daily Trend
            if "timestamp" in df.columns and not df["timestamp"].empty:
                daily_counts = df.groupby(df["timestamp"].dt.date).size()
                if not daily_counts.empty:
                    axes[1, 0].plot(daily_counts.index, daily_counts.values, marker='o')
                    axes[1, 0].set_title('Daily Query Trend')
                    axes[1, 0].set_xlabel('Date')
                    axes[1, 0].set_ylabel('Number of Queries')
                    axes[1, 0].tick_params(axis='x', rotation=45)
                else:
                    axes[1, 0].text(0.5, 0.5, 'No daily data', ha='center', va='center')
                    axes[1, 0].set_title('Daily Query Trend')
            else:
                axes[1, 0].text(0.5, 0.5, 'No timestamp data', ha='center', va='center')
                axes[1, 0].set_title('Daily Query Trend')
            
            # 4. Query Length Distribution
            if "query" in df.columns and not df["query"].empty:
                df["query_length"] = df["query"].str.len()
                axes[1, 1].hist(df["query_length"], bins=20, alpha=0.7)
                axes[1, 1].set_title('Query Length Distribution')
                axes[1, 1].set_xlabel('Characters')
                axes[1, 1].set_ylabel('Frequency')
            else:
                axes[1, 1].text(0.5, 0.5, 'No query data', ha='center', va='center')
                axes[1, 1].set_title('Query Length Distribution')
            
            plt.tight_layout()
            plt.savefig("static/analytics_dashboard.png", dpi=300, bbox_inches='tight')
            plt.close(fig)  # Close the figure to free memory
            print("📊 Analytics dashboard saved to static/analytics_dashboard.png")
            
        except Exception as e:
            print(f"⚠️  Error creating visualizations: {e}")
            # Create a simple placeholder image if visualization fails
            try:
                fig, ax = plt.subplots(1, 1, figsize=(10, 6))
                ax.text(0.5, 0.5, 'Visualization Error\nPlease check your data', 
                       ha='center', va='center', fontsize=16)
                ax.set_title('Analytics Dashboard')
                plt.savefig("static/analytics_dashboard.png", dpi=300, bbox_inches='tight')
                plt.close(fig)
                print("📊 Created placeholder dashboard image")
            except Exception as e2:
                print(f"❌ Could not create placeholder image: {e2}")
    
    def run_analysis(self):
        """Run complete analytics analysis"""
        print("🚀 Starting Analytics Analysis...")
        
        # Load data
        df = self.load_data()
        if df is None or df.empty:
            print("❌ No data available for analysis")
            return None
        
        # Categorize queries
        df = self.categorize_queries(df)
        
        # Generate insights
        insights = self.generate_insights(df)
        
        # Create visualizations
        self.create_visualizations(df)
        
        # Print summary
        print("\n📊 Analytics Summary:")
        print(f"Total Queries: {insights['total_queries']}")
        print(f"Date Range: {insights['date_range']['start']} to {insights['date_range']['end']}")
        print(f"Categories: {insights['categories']}")
        
        return insights

# Run analytics if called directly
if __name__ == "__main__":
    analytics = AnalyticsEngine()
    insights = analytics.run_analysis()