import os
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline

# Define training data
scam_phrases = [
    "Congratulations! You have been selected to win a free iPhone. Claim your reward now!",
    "Double your cryptocurrency. Send BTC to this wallet address and get double back instantly.",
    "URGENT: Your account has been suspended. Log in here to verify your identity and restore access.",
    "Earn $5000 a day working from home. Guaranteed payout, click here to start now.",
    "Exclusive giveaway! Click link to claim your cash reward. Limited time offer.",
    "Your device is infected with 13 viruses! Download this antivirus immediately to secure your files.",
    "Dear customer, suspicious activity detected on your credit card. Update your banking credentials here.",
    "Official PayPal Security Center. Verify your password and social security number.",
    "Win a $1000 Amazon Gift Card! Only 3 minutes left to claim your prize.",
    "Crypto mining investment return guaranteed 200% profit in 24 hours.",
    "Log in to your MetaMask wallet to claim your free airdrop tokens.",
    "Reset your Microsoft password now. Unidentified login attempt detected from Russia.",
    "Free Steam keys! Claim your game codes before the timer runs out.",
    "Get rich quick with this secret trading bot. Sign up for free today.",
    "Netflix account update: payment declined. Click here to update your billing details."
]

safe_phrases = [
    "Welcome to our documentation. Learn how to integrate our APIs and build web applications.",
    "Read the latest technology news, product reviews, and programming tutorials.",
    "Explore our collection of summer apparel. Free shipping on orders over $50.",
    "Create a new document, collaborate with team members, and export files in multiple formats.",
    "Learn about our company mission, meet our leadership team, and check open career roles.",
    "A clean, simple dashboard showing your monthly subscription details and billing settings.",
    "How to install React with Vite and configure TypeScript for your frontend application.",
    "Search results for local restaurants, opening hours, customer reviews, and menus.",
    "A privacy policy explaining how we collect, store, and protect your personal data.",
    "Subscribe to our newsletter to receive weekly updates on open source projects.",
    "The official home of Python. Download the latest version of Python and view docs.",
    "GitHub is where over 100 million developers shape the future of software, join us.",
    "Read our research papers on machine learning, computer vision, and robotics.",
    "Contact customer support if you have questions about your order or need a refund.",
    "A recipe blog featuring healthy recipes, meal planning guides, and grocery lists."
]

def train_model():
    print("Training scam text classification model...")
    
    # Prepare data
    texts = scam_phrases + safe_phrases
    labels = [1] * len(scam_phrases) + [0] * len(safe_phrases) # 1 = Scam, 0 = Safe
    
    # Create pipeline
    pipeline = Pipeline([
        ('vectorizer', TfidfVectorizer(
            ngram_range=(1, 2),
            stop_words='english',
            min_df=1,
            lowercase=True
        )),
        ('classifier', LogisticRegression(C=1.0, max_iter=1000))
    ])
    
    # Train
    pipeline.fit(texts, labels)
    
    # Make directory if not exists
    os.makedirs("app/ml", exist_ok=True)
    
    # Save model and vectorizer separately or as pipeline
    # To follow settings paths:
    # MODEL_PATH: app/ml/model.joblib
    # VECTORIZER_PATH: app/ml/vectorizer.joblib
    
    vectorizer = pipeline.named_steps['vectorizer']
    classifier = pipeline.named_steps['classifier']
    
    joblib.dump(classifier, "app/ml/model.joblib")
    joblib.dump(vectorizer, "app/ml/vectorizer.joblib")
    
    print("Model and Vectorizer trained and saved successfully!")

if __name__ == "__main__":
    train_model()
