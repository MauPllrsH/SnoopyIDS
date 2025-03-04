import numpy as np

def anomaly_boosted_predict(model, X, iso_model, threshold=0.3, iso_weight=0.5):
    """
    Boost model predictions with anomaly detection scores
    - model: main classifier (voting ensemble)
    - X: feature matrix
    - iso_model: isolation forest model
    - threshold: base decision threshold (lower = more sensitive)
    - iso_weight: weight to give to anomaly scores (0-1, higher = more aggressive detection)
    """
    # Get base model prediction probabilities
    base_probs = model.predict_proba(X)[:, 1]
    
    # Get anomaly scores (-1 to 1, where lower is more anomalous)
    raw_scores = iso_model.decision_function(X)
    
    # Normalize scores to 0-1 range and invert (1 = more anomalous)
    min_score, max_score = min(raw_scores), max(raw_scores)
    norm_scores = 1 - ((raw_scores - min_score) / (max_score - min_score + 1e-10))
    
    # Combine scores (weighted average)
    combined_probs = (1 - iso_weight) * base_probs + iso_weight * norm_scores
    
    # Make final predictions
    predictions = (combined_probs >= threshold).astype(int)
    return predictions, combined_probs