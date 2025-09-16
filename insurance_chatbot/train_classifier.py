from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
import pandas as pd
import joblib
import os

def train_classifier():
    """Train and save the insurance query classifier"""
    print("🚀 Starting Insurance Query Classifier Training...")
    
    try:
        # Load dataset
        print("📊 Loading training data...")
        df = pd.read_csv("data/insurance_qa.csv")
        print(f"✅ Loaded {len(df)} training examples")
        
        # Check if we have enough data
        if len(df) < 2:
            print("⚠️  Warning: Very small dataset. Consider adding more training examples.")
        
        # Prepare features and labels
        X = df["question"]
        y = df["category"]
        
        print(f"📝 Categories found: {y.unique()}")
        print(f"📊 Category distribution:\n{y.value_counts()}")
        
        # Split data for validation (if we have enough)
        if len(df) >= 8:  # Need at least 8 examples for meaningful train/test split
            X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)
            print(f"🔄 Split data: {len(X_train)} train, {len(X_test)} test")
        else:
            X_train, y_train = X, y
            X_test, y_test = None, None
            print("📚 Using all data for training (small dataset - skipping validation)")
        
        # Vectorize text
        print("🔤 Creating TF-IDF features...")
        vectorizer = TfidfVectorizer(max_features=1000, stop_words='english')
        X_train_vec = vectorizer.fit_transform(X_train)
        
        # Train classifier
        print("🤖 Training Logistic Regression classifier...")
        clf = LogisticRegression(random_state=42, max_iter=1000)
        clf.fit(X_train_vec, y_train)
        
        # Evaluate model if we have test data
        if X_test is not None:
            X_test_vec = vectorizer.transform(X_test)
            y_pred = clf.predict(X_test_vec)
            accuracy = accuracy_score(y_test, y_pred)
            print(f"📈 Model Accuracy: {accuracy:.2f}")
            print("\n📊 Classification Report:")
            print(classification_report(y_test, y_pred))
        
        # Create models directory if it doesn't exist
        os.makedirs("models", exist_ok=True)
        
        # Save model and vectorizer
        print("💾 Saving trained models...")
        joblib.dump(clf, "models/query_classifier.pkl")
        joblib.dump(vectorizer, "models/vectorizer.pkl")
        
        print("✅ Training completed successfully!")
        print("📁 Models saved to:")
        print("   - models/query_classifier.pkl")
        print("   - models/vectorizer.pkl")
        
        return True
        
    except FileNotFoundError:
        print("❌ Error: Could not find 'data/insurance_qa.csv'")
        print("💡 Make sure you're running this from the insurance_chatbot directory")
        return False
    except Exception as e:
        print(f"❌ Error during training: {e}")
        return False

if __name__ == "__main__":
    success = train_classifier()
    if success:
        print("\n🎉 Classifier training completed! You can now use it in your chatbot.")
    else:
        print("\n💥 Training failed. Please check the error messages above.")