import joblib
import os
import re
import numpy as np

_model_pipeline = None

def load_model(model_path="./data/model/classifier.pkl"):
    global _model_pipeline
    if _model_pipeline is None:
        if not os.path.exists(model_path):
            raise FileNotFoundError(f"Model not found at {model_path}. Run training first.")
        _model_pipeline = joblib.load(model_path)
    return _model_pipeline

def clean_text(text: str) -> str:
    """Pre-cleans email text (lowercased, punctuation stripped) as expected by the model."""
    if not text:
        return ""
    text = text.lower()
    text = re.sub(r'[^\w\s]', ' ', text)
    text = re.sub(r'\s+', ' ', text).strip()
    return text

def score_email(subject: str, body_text: str) -> dict:
    """
    Combines subject + body_text internally (to match text_combined format),
    then returns:
      {
        "phishing_probability": float,
        "predicted_label": "phishing" | "legitimate",
        "model_version": string,
        "top_indicative_terms": [string]
      }
    """
    subject = subject or ""
    body_text = body_text or ""

    combined = f"{subject} {body_text}"
    cleaned = clean_text(combined)

    model = load_model()

    probs = model.predict_proba([cleaned])[0]
    prob_phishing = float(probs[1])
    result_label = "phishing" if prob_phishing >= 0.5 else "legitimate"

    top_terms = []
    try:
        tfidf = model.named_steps['tfidf']
        clf = model.named_steps['clf']
        feature_names = tfidf.get_feature_names_out()

        # Sparse TF-IDF vector for the input text
        vec = tfidf.transform([cleaned])

        # LR coef_[0] = weight for class 1 (phishing).
        # Element-wise multiply: only terms present in input (non-zero TF-IDF) contribute.
        phishing_coefs = clf.coef_[0]              # shape: (n_features,)
        weighted = vec.toarray()[0] * phishing_coefs  # shape: (n_features,)

        # Rank by contribution toward the predicted class
        if result_label == "phishing":
            ranked = np.argsort(weighted)[::-1]    # highest positive = most phishing
        else:
            ranked = np.argsort(weighted)           # most negative = most legitimate

        # Collect up to 5 terms that are actually present in the input
        for idx in ranked:
            if len(top_terms) >= 5:
                break
            if vec[0, idx] > 0:                    # term appeared in the text
                top_terms.append(str(feature_names[idx]))
    except Exception:
        pass

    return {
        "phishing_probability": prob_phishing,
        "predicted_label": result_label,
        "model_version": "baseline_v1.0",
        "top_indicative_terms": top_terms
    }
