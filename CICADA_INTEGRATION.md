# Cicada Integration with SnoopyIDS

This document explains how to integrate Cicada's advanced anomaly detection with SnoopyIDS.

## Overview

SnoopyIDS has been enhanced to use Cicada's more advanced anomaly detection capabilities. This integration involves:

1. Using Cicada's more sophisticated feature extraction
2. Leveraging Cicada's advanced ensemble model with anomaly boosting
3. Maintaining consistent feature alignment between training and inference

## How to Use

### Training the Model in Cicada

1. Train your model in Cicada as usual (This happens automatically)
2. The enhanced train.py will create a `complete_model_package.joblib` file in Cicada's models directory

### Deploying to SnoopyIDS

1. Copy the `complete_model_package.joblib` file from Cicada to SnoopyIDS:
   ```bash
   cp /path/to/Cicada/model/complete_model_package.joblib /path/to/SnoopyIDS/model/
   ```
   Note: Both Cicada and SnoopyIDS use the `model` directory for consistency.

2. Start SnoopyIDS normally - it will automatically detect and use the Cicada model package

## How It Works

1. SnoopyIDS first attempts to load the complete model package from Cicada
2. If found, it uses Cicada's feature extraction and alignment for predictions
3. It also uses Cicada's anomaly boosting capability for better detection
4. If the complete package is not found, it falls back to the original SnoopyIDS behavior

## Troubleshooting

If you encounter issues with the integration:

1. Check that all required Python packages are installed in SnoopyIDS:
   ```bash
   pip install scikit-learn pandas numpy scipy xgboost
   ```

2. Ensure the model package has been properly copied to the SnoopyIDS models directory

3. Check SnoopyIDS logs for any errors related to the model loading or feature extraction

## Feature Comparison

| Feature                  | Cicada | SnoopyIDS with Integration | Original SnoopyIDS |
|--------------------------|--------|----------------------------|-------------------|
| Feature count            | 40+    | 40+                        | 10                |
| Entropy analysis         | ✅     | ✅                         | ❌                |
| Path traversal detection | ✅     | ✅                         | ❌                |
| Ensemble model           | ✅     | ✅                         | ❌                |
| Anomaly boosting         | ✅     | ✅                         | ❌                |
| Threshold optimization   | ✅     | ✅                         | ❌                |
| Rule-based detection     | ❌     | ✅                         | ✅                |
| Automatic rule generation| ❌     | ✅                         | ✅                |