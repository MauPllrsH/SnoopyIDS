import pandas as pd
import re
import numpy as np
import warnings
from utils.logger_config import logger

# Suppress warnings about regex match groups in str.contains()
warnings.filterwarnings('ignore', message=".*match groups.*", category=UserWarning)

# Import entropy from scipy.stats
from scipy.stats import entropy


def extract_features(data):
    """Enhanced feature extraction for improved attack detection - 
    EXACT copy from Cicada for consistent feature extraction"""
    
    # Base features
    features = pd.DataFrame({
        'method': data['method'],
        'has_body': data['body'].notna().astype(int),
        'header_count': data['headers'].apply(lambda x: len(x) if isinstance(x, dict) else 0),
        'has_query': data['query'].notna().astype(int),
        'content_type': data['headers'].apply(lambda x: 1 if 'content-type' in str(x).lower() else 0),
        'user_agent': data['headers'].apply(lambda x: 1 if 'user-agent' in str(x).lower() else 0),
        'body_length': data['body'].fillna('').str.len(),
        'path_depth': data['path'].str.count('/'),
        
        # Enhanced SQL injection detection
        'has_sql_keywords': data['body'].fillna('').str.lower().str.contains(
            'select|from|where|union|insert|update|delete|drop|alter|exec|execute|sp_|xp_|declare|cast|1=1|--|\bor\s+\d+=\d+|\bunion\s+select|\band\s+\d+=\d+|\'|\"').astype(int) |
            data['query'].fillna('').str.lower().str.contains(
            'select|from|where|union|insert|update|delete|drop|alter|exec|execute|sp_|xp_|declare|cast|1=1|--|\bor\s+\d+=\d+|\bunion\s+select|\band\s+\d+=\d+|\'|\"').astype(int) |
            data['path'].str.lower().str.contains(
            'select|from|where|union|insert|update|delete|drop|alter|exec|execute|sp_|xp_|declare|cast|1=1|--|\bor\s+\d+=\d+|\bunion\s+select|\band\s+\d+=\d+|\'|\"').astype(int),
            
        # Improved XSS detection with broader pattern coverage including a href and common attack phrases
        'has_script_tags': data['body'].fillna('').str.lower().str.contains(
            '<script|javascript:|on\w+=|<img|<iframe|<svg|alert\\(|eval\\(|document\\.|<alert|<alart|<a\\s+href|onerror|onclick|onload|\\.cookie|\\.innerhtml|fromcharcode|\\\\x[0-9a-f]{2}|&#x[0-9a-f]{2}|phishing|steal|hack|\\.php|\\.jsp|\\.aspx|attack').astype(int) |
            data['query'].fillna('').str.lower().str.contains(
            '<script|javascript:|on\w+=|<img|<iframe|<svg|alert\\(|eval\\(|document\\.|<alert|<alart|<a\\s+href|onerror|onclick|onload|\\.cookie|\\.innerhtml|fromcharcode|\\\\x[0-9a-f]{2}|&#x[0-9a-f]{2}|phishing|steal|hack|\\.php|\\.jsp|\\.aspx|attack').astype(int),
            
        # Enhanced file scanning detection
        'is_env_file_scan': data['path'].str.contains('\.env|\.config|\.cfg|\.ini|\.properties|\.yaml|\.yml|\.json|\.xml').astype(int),
        'is_sensitive_file_scan': data['path'].str.contains('passwd|shadow|config|wp-config|credentials|\.git|\.ssh|\.htaccess|\.htpasswd|web\.config|php\.ini').astype(int),
        
        # Better path traversal detection
        'path_has_traversal': data['path'].str.contains('\.\.\/|\.\.%2F|%2e%2e%2f|%252e%252e%252f|%c0%ae%c0%ae%c0%af').astype(int),
        
        # Command injection detection
        'has_bash_chars': data['path'].str.contains('\$|\`|\||\;|\&|\/bin\/|\-\-version|\-\-help').astype(int) | 
                           data['query'].fillna('').str.contains('\$|\`|\||\;|\&|\/bin\/|\-\-version|\-\-help').astype(int) |
                           data['body'].fillna('').str.contains('\$|\`|\||\;|\&|\/bin\/|\-\-version|\-\-help').astype(int)
    })
    
    # Add advanced detection features
    
    # Suspicious user agent detection - fixed regex to use non-capturing groups
    features['suspicious_user_agent'] = data['headers'].apply(
        lambda x: 1 if isinstance(x, dict) and 'user-agent' in str(x).lower() and 
        bool(re.search(r'(?:sqlmap|nikto|nessus|nmap|wpscan|burp|acunetix|gobuster|dirbuster|zgrab|masscan|python-requests|curl|wget|scanner|metasploit)',
                      str(x.get('user-agent', '')).lower()))
        else 0
    )
    
    # Calculate entropy for path and query strings
    def calculate_entropy(text):
        if not isinstance(text, str) or len(text) < 2:
            return 0
        
        # Count character frequencies
        try:
            text_bytes = text.encode('utf-8', errors='ignore')
            if len(text_bytes) < 2:
                return 0
                
            # Calculate entropy
            byte_array = np.frombuffer(text_bytes, dtype=np.uint8)
            freq = np.bincount(byte_array)
            freq = freq[freq > 0]  # Only use non-zero frequencies
            
            return entropy(freq, base=2)
                
        except Exception:
            return 0

    # Apply entropy calculation
    features['path_entropy'] = data['path'].apply(calculate_entropy)
    features['query_entropy'] = data['query'].fillna('').apply(calculate_entropy)
    
    # Detect encoded content (base64, hex, url encoding)
    def has_encoded_content(text):
        if not isinstance(text, str) or len(text) <= 1:
            return 0
        # Base64 pattern
        if bool(re.search(r'[A-Za-z0-9+/]{20,}={0,2}', text)):
            return 1
        # Excessive hex encoding - fixed with non-capturing group
        if bool(re.search(r'(?:%[0-9A-Fa-f]{2}){10,}', text)):
            return 1
        # URL encoded characters ratio
        encoded_chars = len(re.findall(r'%[0-9A-Fa-f]{2}', text))
        if encoded_chars > 0 and encoded_chars / len(text) > 0.3:
            return 1
        return 0
    
    features['path_encoded'] = data['path'].apply(has_encoded_content)
    features['query_encoded'] = data['query'].fillna('').apply(has_encoded_content)
    features['body_encoded'] = data['body'].fillna('').apply(has_encoded_content)
    
    # Detect unusual HTTP methods
    features['unusual_method'] = data['method'].apply(
        lambda x: 0 if x in ['GET', 'POST', 'HEAD', 'OPTIONS', 'PUT', 'DELETE'] else 1
    )
    
    # Detect suspicious paths
    features['suspicious_path'] = data['path'].str.contains(
        'admin|manage|root|backup|console|test|temp|tmp|dev|phpinfo|shell|cgi-bin|wp-admin|admin\.php|setup|install'
    ).astype(int)
    
    # Log4j/Log4Shell detection
    features['log4j_attempt'] = data['path'].str.contains(r'\$\{jndi:').astype(int) | \
                              data['query'].fillna('').str.contains(r'\$\{jndi:').astype(int) | \
                              data['body'].fillna('').str.contains(r'\$\{jndi:').astype(int) | \
                              data['headers'].apply(lambda x: 1 if isinstance(x, dict) and 
                                                   any(r'${jndi:' in str(v).lower() for v in x.values()) else 0)
    
    # Cross-domain includes detection - fixed regex to remove capture groups
    features['remote_includes'] = data['path'].str.contains(r'=(?:https?:|www\.)').astype(int) | \
                                 data['query'].fillna('').str.contains(r'=(?:https?:|www\.)').astype(int)
    
    # Number of parameters in the request
    features['param_count'] = data['query'].fillna('').apply(lambda x: x.count('='))
    
    # Request size anomaly 
    features['large_request'] = ((features['body_length'] > 8000) | (data['path'].str.len() > 255)).astype(int)
    
    # Add padding to ensure we have 82 features as expected by the model
    current_count = features.shape[1]
    if current_count < 82:
        for i in range(current_count, 82):
            features[f'padding_{i}'] = 0
    elif current_count > 82:
        features = features.iloc[:, :82]
    
    return features
