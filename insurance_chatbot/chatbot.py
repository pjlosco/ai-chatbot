from transformers import pipeline
import pandas as pd
import joblib
import os
import sys

def load_models():
    """Load all required models and data"""
    print("🚀 Initializing Insurance Chatbot...")
    
    # Load Q&A dataset
    print("📊 Loading Q&A database...")
    try:
        df = pd.read_csv("data/insurance_qa.csv")
        print(f"✅ Loaded {len(df)} Q&A examples")
    except FileNotFoundError:
        print("❌ Error: Could not find 'data/insurance_qa.csv'")
        print("💡 Make sure you're running from the insurance_chatbot directory")
        sys.exit(1)
    
    # Load pre-trained LLM
    print("🤖 Loading DistilBERT model (this may take 30+ seconds)...")
    try:
        nlp = pipeline("question-answering", model="distilbert-base-uncased-distilled-squad")
        print("✅ DistilBERT model loaded successfully")
    except Exception as e:
        print(f"❌ Error loading DistilBERT: {e}")
        sys.exit(1)
    
    # Load ML classifier if available
    classifier = None
    vectorizer = None
    if os.path.exists("models/query_classifier.pkl") and os.path.exists("models/vectorizer.pkl"):
        try:
            print("🧠 Loading trained classifier...")
            classifier = joblib.load("models/query_classifier.pkl")
            vectorizer = joblib.load("models/vectorizer.pkl")
            print("✅ ML Classifier loaded successfully!")
        except Exception as e:
            print(f"⚠️  Warning: Could not load classifier: {e}")
            print("💡 Run 'python train_classifier.py' to train the classifier")
    else:
        print("⚠️  ML Classifier not found. Run 'python train_classifier.py' first.")
    
    return df, nlp, classifier, vectorizer

# Load all models and data
df, nlp, classifier, vectorizer = load_models()

def answer_query(question):
    """Answer an insurance question using multiple approaches"""
    
    # Step 1: Check for exact matches in our database
    for _, row in df.iterrows():
        if question.lower() in row["question"].lower():
            print(f"📚 Found exact match in database")
            return row["answer"]
    
    # Step 2: Use ML classifier to categorize the question
    predicted_category = None
    if classifier and vectorizer:
        try:
            question_vec = vectorizer.transform([question])
            predicted_category = classifier.predict(question_vec)[0]
            confidence = classifier.predict_proba(question_vec).max()
            print(f"🔍 Detected category: {predicted_category} (confidence: {confidence:.2f})")
        except Exception as e:
            print(f"⚠️  Classifier error: {e}")
    
    # Step 3: Use LLM with category-specific context
    insurance_context = """
    Health insurance plans include HMOs (Health Maintenance Organizations) which require you to choose a primary care physician and get referrals for specialists. 
    PPOs (Preferred Provider Organizations) offer more flexibility with in-network and out-of-network coverage. 
    EPOs (Exclusive Provider Organizations) are similar to PPOs but don't cover out-of-network care except in emergencies.
    A deductible is the amount you pay for covered health care services before your insurance plan starts to pay. For example, if your deductible is $1,000, you pay the first $1,000 of covered services yourself.
    A copay is a fixed amount you pay for a covered health care service, usually when you receive the service.
    A premium is the amount you pay for your health insurance every month.
    Enrollment typically happens during open enrollment periods or through special enrollment periods for qualifying life events.
    The Affordable Care Act (ACA) provides marketplace plans with subsidies based on income.
    """
    
    # Add category-specific context
    if predicted_category == "Enrollment":
        insurance_context += " For enrollment questions, visit HealthCare.gov or contact a licensed insurance broker."
    elif predicted_category == "Plan Type":
        insurance_context += " Plan types differ in cost, flexibility, and provider networks."
    
    print(f"🤖 Using AI to generate response...")
    result = nlp(question=question, context=insurance_context)
    
    # Return response with confidence check
    if result["score"] > 0.05:  # Lowered threshold from 0.1 to 0.05
        return result["answer"]
    else:
        return "I don't have enough information to answer that question accurately. Please contact your insurance provider for specific details."

def main():
    """Main chatbot interface"""
    print("\n" + "="*60)
    print("🏥 Welcome to the AI-Powered Insurance Query Assistant!")
    print("="*60)
    print("I can help you with questions about:")
    print("• Health insurance plan types (HMO, PPO, EPO)")
    print("• Enrollment processes and deadlines")
    print("• Coverage and benefits")
    print("• ACA marketplace plans")
    print("\nType 'quit' to exit, 'help' for more options")
    print("="*60)
    
    while True:
        try:
            query = input("\n💬 Ask your insurance question: ").strip()
            
            if query.lower() == 'quit':
                print("👋 Thank you for using the Insurance Assistant!")
                break
            elif query.lower() == 'help':
                print("\n📚 Available commands:")
                print("• Ask any insurance question")
                print("• 'quit' - Exit the program")
                print("• 'help' - Show this help message")
                continue
            elif not query:
                print("❓ Please enter a question or 'quit' to exit")
                continue
            
            print(f"\n🔍 Processing: '{query}'")
            print("-" * 50)
            answer = answer_query(query)
            print(f"\n💡 Answer: {answer}")
            print("-" * 50)
            
        except KeyboardInterrupt:
            print("\n\n👋 Goodbye!")
            break
        except Exception as e:
            print(f"\n❌ Error: {e}")
            print("Please try again or type 'quit' to exit")

if __name__ == "__main__":
    main()