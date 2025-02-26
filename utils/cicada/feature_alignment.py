import logging

import numpy as np
from scipy.sparse import issparse

from utils.cicada.feature_extractor import extract_features


def add_endpoint_features(X, data):
    """Add more sophisticated features"""
    # Add endpoint-specific features
    X['is_search_endpoint'] = data['path'].str.contains('/search').astype(int)
    X['is_login_endpoint'] = data['path'].str.contains('/login').astype(int)
    X['is_root_endpoint'] = (data['path'] == '/').astype(int)

    # Add complexity metrics
    X['path_depth'] = data['path'].str.count('/')
    X['path_length'] = data['path'].str.len()

    # Query analysis
    X['has_query'] = data['query'].str.len() > 0
    X['query_param_count'] = data['query'].str.count('&') + 1

    # Additional security-focused features
    X['has_special_chars'] = data['path'].str.contains('[<>{}()\'"]').astype(int)
    X['has_sql_keywords'] = data['path'].str.lower().str.contains(
        'select|insert|update|delete|union|drop'
    ).astype(int)

    return X


def extract_features_consistent(data, vectorizer, preprocessor, all_feature_names, onehot=None):
    """Extract features ensuring consistency with training features"""
    # Extract base features
    X = extract_features(data)

    # Add the endpoint features that were present during training
    X = add_endpoint_features(X, data)

    path_features = vectorizer.transform(data['path'].fillna(''))

    categorical_columns = ['method']
    numerical_columns = [col for col in X.columns if col not in categorical_columns]

    # Get onehot encoder from preprocessor if not provided
    if onehot is None:
        try:
            onehot = preprocessor.named_transformers_['cat']
        except (KeyError, AttributeError) as e:
            # Try alternative way to get transformer
            try:
                for name, transformer, _ in preprocessor.transformers_:
                    if name == 'cat':
                        onehot = transformer
                        break
            except Exception as nested_e:
                logging.error(f"Could not extract onehot encoder: {nested_e}")
                raise ValueError(f"Failed to extract onehot encoder: {e}, {nested_e}")

    try:
        X_cat = onehot.transform(X[categorical_columns])
        X_num = preprocessor.named_transformers_['num'].transform(X[numerical_columns])
    except (ValueError, KeyError, AttributeError) as e:
        print("Feature mismatch detected. Available features:", X.columns.tolist())
        print("Expected numerical features:", numerical_columns)
        
        # Handle unknown categories by replacing with known ones
        if isinstance(e, ValueError) and "unknown categories" in str(e).lower():
            try:
                # For categorical columns with unknown values, replace with the first known category
                for i, col in enumerate(categorical_columns):
                    known_categories = onehot.categories_[i]
                    X[col] = X[col].apply(lambda x: x if x in known_categories else known_categories[0])
                # Try transform again
                X_cat = onehot.transform(X[categorical_columns])
            except Exception as fix_e:
                logging.error(f"Failed to handle unknown categories: {fix_e}")
                raise ValueError(f"Cannot process features after attempted fix: {fix_e}")
        else:
            raise e
        
        try:
            X_num = preprocessor.named_transformers_['num'].transform(X[numerical_columns])
        except Exception as num_e:
            logging.error(f"Failed to transform numerical features: {num_e}")
            raise ValueError(f"Cannot process numerical features: {num_e}")

    if issparse(X_num):
        X_num = X_num.toarray()
    if issparse(X_cat):
        X_cat = X_cat.toarray()
    if issparse(path_features):
        path_features = path_features.toarray()

    # Validate shapes before combining
    expected_features = len(all_feature_names)
    combined_features = X_num.shape[1] + X_cat.shape[1] + path_features.shape[1]
    if combined_features != expected_features:
        logging.warning(f"Feature count mismatch. Expected {expected_features}, got {combined_features}")
        # We'll continue anyway, but log the warning

    X_combined = np.hstack((X_num, X_cat, path_features))

    return X_combined
