import numpy as np
import pandas as pd
import joblib
import logging
from typing import Dict, List, Tuple, Optional, Union
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
from sklearn.model_selection import train_test_split
# TensorFlow imports commented out due to DLL issues
# import tensorflow as tf
# from tensorflow import keras
# from tensorflow.keras import layers
import warnings
warnings.filterwarnings("ignore")

logger = logging.getLogger(__name__)

class NetworkAnomalyDetector:
    """
    Machine Learning pipeline for network anomaly detection.
    
    Implements multiple ML models:
    - Isolation Forest (unsupervised)
    - One-Class SVM (unsupervised)
    - AutoEncoder (neural network)
    """
    
    def __init__(self, models_config: Optional[Dict] = None):
        """
        Initialize the anomaly detector.
        
        Args:
            models_config: Configuration for ML models
        """
        self.models = {}
        self.models_config = models_config or self._get_default_config()
        self.feature_names = []
        self.is_trained = False
        
        # Initialize models
        self._initialize_models()
        
        logger.info("NetworkAnomalyDetector initialized")
    
    def _get_default_config(self) -> Dict:
        """Get default configuration for ML models."""
        return {
            'isolation_forest': {
                'contamination': 0.1,  # Expected proportion of anomalies
                'random_state': 42,
                'n_estimators': 100
            },
            'one_class_svm': {
                'nu': 0.1,  # Proportion of outliers
                'kernel': 'rbf',
                'gamma': 'scale'
            },
            'autoencoder': {
                'encoding_dim': 32,
                'hidden_layers': [64, 32],
                'epochs': 50,
                'batch_size': 32,
                'validation_split': 0.2
            }
        }
    
    def _initialize_models(self):
        """Initialize ML models with configuration."""
        try:
            # Isolation Forest
            self.models['isolation_forest'] = IsolationForest(
                contamination=self.models_config['isolation_forest']['contamination'],
                random_state=self.models_config['isolation_forest']['random_state'],
                n_estimators=self.models_config['isolation_forest']['n_estimators']
            )
            
            # One-Class SVM
            self.models['one_class_svm'] = OneClassSVM(
                nu=self.models_config['one_class_svm']['nu'],
                kernel=self.models_config['one_class_svm']['kernel'],
                gamma=self.models_config['one_class_svm']['gamma']
            )
            
            # AutoEncoder will be built dynamically based on input shape
            self.models['autoencoder'] = None
            
            logger.info("ML models initialized successfully")
            
        except Exception as e:
            logger.error(f"Error initializing models: {e}")
    
    def _build_autoencoder(self, input_dim: int):
        """
        Build AutoEncoder neural network (disabled due to TensorFlow issues).
        
        Args:
            input_dim: Number of input features
            
        Returns:
            None (AutoEncoder disabled)
        """
        logger.warning("AutoEncoder disabled due to TensorFlow DLL issues")
        return None
    
    def train_models(self, X_train: np.ndarray, X_test: Optional[np.ndarray] = None) -> Dict:
        """
        Train all ML models on the training data.
        
        Args:
            X_train: Training features
            X_test: Test features (optional)
            
        Returns:
            Dictionary with training results
        """
        try:
            logger.info(f"Training models on {X_train.shape[0]} samples with {X_train.shape[1]} features")
            
            results = {}
            
            # Train Isolation Forest
            logger.info("Training Isolation Forest...")
            self.models['isolation_forest'].fit(X_train)
            if_train_pred = self.models['isolation_forest'].predict(X_train)
            if_train_scores = self.models['isolation_forest'].decision_function(X_train)
            
            results['isolation_forest'] = {
                'train_predictions': if_train_pred,
                'train_scores': if_train_scores,
                'anomaly_count': np.sum(if_train_pred == -1)
            }
            
            # Train One-Class SVM
            logger.info("Training One-Class SVM...")
            self.models['one_class_svm'].fit(X_train)
            svm_train_pred = self.models['one_class_svm'].predict(X_train)
            svm_train_scores = self.models['one_class_svm'].decision_function(X_train)
            
            results['one_class_svm'] = {
                'train_predictions': svm_train_pred,
                'train_scores': svm_train_scores,
                'anomaly_count': np.sum(svm_train_pred == -1)
            }
            
            # Train AutoEncoder (disabled)
            logger.info("Skipping AutoEncoder training (disabled)")
            results['autoencoder'] = {
                'history': {},
                'train_errors': np.zeros(len(X_train)),
                'threshold': 0.0
            }
            
            self.is_trained = True
            logger.info("All models trained successfully")
            
            return results
            
        except Exception as e:
            logger.error(f"Error training models: {e}")
            return {}
    
    def predict_anomaly(self, X: np.ndarray, model_name: str = 'ensemble') -> Dict:
        """
        Predict anomalies using specified model or ensemble.
        
        Args:
            X: Feature matrix
            model_name: Model to use ('isolation_forest', 'one_class_svm', 'autoencoder', 'ensemble')
            
        Returns:
            Dictionary with predictions and scores
        """
        try:
            if not self.is_trained:
                logger.error("Models not trained. Call train_models first.")
                return {}
            
            results = {}
            
            if model_name == 'ensemble' or model_name == 'isolation_forest':
                # Isolation Forest predictions
                if_pred = self.models['isolation_forest'].predict(X)
                if_scores = self.models['isolation_forest'].decision_function(X)
                
                # Convert scores to 0-100 scale
                if_scores_normalized = self._normalize_scores(if_scores, method='isolation_forest')
                
                results['isolation_forest'] = {
                    'predictions': if_pred,
                    'scores': if_scores_normalized,
                    'anomaly_count': np.sum(if_pred == -1)
                }
            
            if model_name == 'ensemble' or model_name == 'one_class_svm':
                # One-Class SVM predictions
                svm_pred = self.models['one_class_svm'].predict(X)
                svm_scores = self.models['one_class_svm'].decision_function(X)
                
                # Convert scores to 0-100 scale
                svm_scores_normalized = self._normalize_scores(svm_scores, method='one_class_svm')
                
                results['one_class_svm'] = {
                    'predictions': svm_pred,
                    'scores': svm_scores_normalized,
                    'anomaly_count': np.sum(svm_pred == -1)
                }
            
            if model_name == 'ensemble' or model_name == 'autoencoder':
                # AutoEncoder predictions
                if self.models['autoencoder'] is not None:
                    reconstructions = self.models['autoencoder'].predict(X)
                    reconstruction_errors = np.mean(np.square(X - reconstructions), axis=1)
                    
                    # Convert errors to anomaly scores (0-100)
                    threshold = results.get('autoencoder', {}).get('threshold', np.percentile(reconstruction_errors, 95))
                    ae_scores = np.clip((reconstruction_errors / threshold) * 50, 0, 100)
                    
                    # Binary predictions based on threshold
                    ae_pred = np.where(reconstruction_errors > threshold, -1, 1)
                    
                    results['autoencoder'] = {
                        'predictions': ae_pred,
                        'scores': ae_scores,
                        'reconstruction_errors': reconstruction_errors,
                        'anomaly_count': np.sum(ae_pred == -1)
                    }
            
            # Ensemble predictions
            if model_name == 'ensemble':
                ensemble_scores = self._combine_ensemble_scores(results)
                ensemble_pred = np.where(ensemble_scores > 60, -1, 1)  # Threshold at 60
                
                results['ensemble'] = {
                    'predictions': ensemble_pred,
                    'scores': ensemble_scores,
                    'anomaly_count': np.sum(ensemble_pred == -1)
                }
            
            return results
            
        except Exception as e:
            logger.error(f"Error predicting anomalies: {e}")
            return {}
    
    def _normalize_scores(self, scores: np.ndarray, method: str) -> np.ndarray:
        """
        Normalize anomaly scores to 0-100 range.
        
        Args:
            scores: Raw anomaly scores
            method: Normalization method
            
        Returns:
            Normalized scores (0-100)
        """
        try:
            if method == 'isolation_forest':
                # Isolation Forest scores are already in reasonable range
                # Convert to 0-100 scale
                min_score, max_score = scores.min(), scores.max()
                if max_score > min_score:
                    normalized = ((scores - min_score) / (max_score - min_score)) * 100
                else:
                    normalized = np.full_like(scores, 50)  # Default middle value
                return normalized
            
            elif method == 'one_class_svm':
                # One-Class SVM scores can be negative
                # Convert to 0-100 scale
                min_score, max_score = scores.min(), scores.max()
                if max_score > min_score:
                    normalized = ((scores - min_score) / (max_score - min_score)) * 100
                else:
                    normalized = np.full_like(scores, 50)
                return normalized
            
            else:
                return scores
                
        except Exception as e:
            logger.error(f"Error normalizing scores: {e}")
            return np.full_like(scores, 50)
    
    def _combine_ensemble_scores(self, results: Dict) -> np.ndarray:
        """
        Combine scores from multiple models for ensemble prediction.
        
        Args:
            results: Dictionary with individual model results
            
        Returns:
            Combined ensemble scores
        """
        try:
            scores_list = []
            weights = []
            
            # Collect scores and weights
            if 'isolation_forest' in results:
                scores_list.append(results['isolation_forest']['scores'])
                weights.append(0.4)  # Weight for Isolation Forest
            
            if 'one_class_svm' in results:
                scores_list.append(results['one_class_svm']['scores'])
                weights.append(0.3)  # Weight for One-Class SVM
            
            if 'autoencoder' in results:
                scores_list.append(results['autoencoder']['scores'])
                weights.append(0.3)  # Weight for AutoEncoder
            
            if not scores_list:
                logger.warning("No model scores available for ensemble")
                return np.array([])
            
            # Normalize weights
            weights = np.array(weights)
            weights = weights / weights.sum()
            
            # Calculate weighted average
            ensemble_scores = np.zeros_like(scores_list[0])
            for scores, weight in zip(scores_list, weights):
                ensemble_scores += scores * weight
            
            return ensemble_scores
            
        except Exception as e:
            logger.error(f"Error combining ensemble scores: {e}")
            return np.array([])
    
    def get_risk_level(self, score: float) -> str:
        """
        Convert anomaly score to risk level.
        
        Args:
            score: Anomaly score (0-100)
            
        Returns:
            Risk level string
        """
        if score >= 80:
            return "High"
        elif score >= 60:
            return "Medium"
        else:
            return "Low"
    
    def explain_anomaly(self, features: np.ndarray, model_name: str = 'ensemble') -> str:
        """
        Generate explanation for why a packet is flagged as anomalous.
        
        Args:
            features: Feature vector
            model_name: Model used for prediction
            
        Returns:
            Explanation string
        """
        try:
            explanations = []
            
            # Check individual features for anomalies
            if len(features) >= len(self.feature_names):
                for i, (feature_name, value) in enumerate(zip(self.feature_names, features)):
                    if 'packet_size' in feature_name and value > 1500:
                        explanations.append("Large packet size detected")
                    elif 'inter_arrival_time' in feature_name and value < 0.001:
                        explanations.append("Very high packet rate")
                    elif 'port_diversity' in feature_name and value > 0.5:
                        explanations.append("High port diversity (possible port scan)")
                    elif 'ip_entropy' in feature_name and value > 0.8:
                        explanations.append("High IP diversity")
                    elif 'packets_per_second' in feature_name and value > 100:
                        explanations.append("High packets per second rate")
            
            if explanations:
                return "; ".join(explanations)
            else:
                return "Anomalous pattern detected by ML model"
                
        except Exception as e:
            logger.error(f"Error generating explanation: {e}")
            return "Anomaly detected"
    
    def save_models(self, filepath_prefix: str):
        """
        Save trained models to disk.
        
        Args:
            filepath_prefix: Prefix for model files
        """
        try:
            # Save scikit-learn models
            for model_name in ['isolation_forest', 'one_class_svm']:
                if model_name in self.models and self.models[model_name] is not None:
                    model_path = f"{filepath_prefix}_{model_name}.joblib"
                    joblib.dump(self.models[model_name], model_path)
                    logger.info(f"Saved {model_name} to {model_path}")
            
            # Save AutoEncoder (disabled)
            logger.info("AutoEncoder saving skipped (disabled)")
            
            # Save detector metadata
            metadata = {
                'feature_names': self.feature_names,
                'is_trained': self.is_trained,
                'models_config': self.models_config
            }
            metadata_path = f"{filepath_prefix}_metadata.joblib"
            joblib.dump(metadata, metadata_path)
            logger.info(f"Saved metadata to {metadata_path}")
            
        except Exception as e:
            logger.error(f"Error saving models: {e}")
    
    def load_models(self, filepath_prefix: str):
        """
        Load trained models from disk.
        
        Args:
            filepath_prefix: Prefix for model files
        """
        try:
            # Load scikit-learn models
            for model_name in ['isolation_forest', 'one_class_svm']:
                model_path = f"{filepath_prefix}_{model_name}.joblib"
                try:
                    self.models[model_name] = joblib.load(model_path)
                    logger.info(f"Loaded {model_name} from {model_path}")
                except FileNotFoundError:
                    logger.warning(f"Model file not found: {model_path}")
            
            # Load AutoEncoder (disabled)
            logger.info("AutoEncoder loading skipped (disabled)")
            
            # Load metadata
            metadata_path = f"{filepath_prefix}_metadata.joblib"
            try:
                metadata = joblib.load(metadata_path)
                self.feature_names = metadata['feature_names']
                self.is_trained = metadata['is_trained']
                self.models_config = metadata['models_config']
                logger.info(f"Loaded metadata from {metadata_path}")
            except FileNotFoundError:
                logger.warning(f"Metadata file not found: {metadata_path}")
            
        except Exception as e:
            logger.error(f"Error loading models: {e}")

def main():
    """
    Test the anomaly detector with sample data.
    """
    # Create sample data
    np.random.seed(42)
    n_samples = 1000
    n_features = 20
    
    # Generate normal data
    X_normal = np.random.normal(0, 1, (n_samples, n_features))
    
    # Generate some anomalies
    X_anomalies = np.random.normal(3, 1, (50, n_features))
    X = np.vstack([X_normal, X_anomalies])
    
    print(f"Generated {X.shape[0]} samples with {X.shape[1]} features")
    
    # Initialize detector
    detector = NetworkAnomalyDetector()
    
    # Train models
    results = detector.train_models(X)
    print(f"Training completed. Anomalies detected:")
    for model_name, result in results.items():
        if 'anomaly_count' in result:
            print(f"  {model_name}: {result['anomaly_count']} anomalies")
    
    # Test predictions
    predictions = detector.predict_anomaly(X[:100], model_name='ensemble')
    if 'ensemble' in predictions:
        ensemble_result = predictions['ensemble']
        print(f"\nEnsemble predictions on test data:")
        print(f"  Anomalies detected: {ensemble_result['anomaly_count']}")
        print(f"  Score range: {ensemble_result['scores'].min():.2f} - {ensemble_result['scores'].max():.2f}")
        
        # Show risk levels
        risk_levels = [detector.get_risk_level(score) for score in ensemble_result['scores'][:10]]
        print(f"  Risk levels (first 10): {risk_levels}")

if __name__ == "__main__":
    main()
