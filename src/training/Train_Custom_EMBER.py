import os
import json
import numpy as np
import lightgbm as lgb
import ember

# --- ×ª×™×§×•× ×™ ×ª××™×ž×•×ª Numpy ---
if not hasattr(np, 'int'): np.int = int
if not hasattr(np, 'bool'): np.bool = bool
if not hasattr(np, 'float'): np.float = float
if not hasattr(np, 'object'): np.object = object

# ==========================================
# ×”× ×ª×™×‘×™× ×©×œ×š
# ==========================================
EMBER_DIR = r"C:\Users\omri9\Desktop\School\Final Project\data\datasets"
MY_BLINDSPOTS = r"C:\Users\omri9\Desktop\School\Final Project\data\datasets\malware_blindspots_new.json"
MY_CLEAN_FILES = r"C:\Users\omri9\Desktop\School\Final Project\data\datasets\modern_clean_files.json"
NEW_MODEL_OUT = r"C:\Users\omri9\Desktop\School\Final Project\final\AntivirusAI_2026_Perfect_V4.txt"

def load_json_features(filepath):
    """×¤×•× ×§×¦×™×™×ª ×¢×–×¨ ×œ×˜×¢×™× ×ª ×”× ×ª×•× ×™× ×©×œ×š"""
    with open(filepath, 'r', encoding='utf-8') as f:
        data = json.load(f)
    X = np.array([item["features"] for item in data], dtype=np.float32)
    y = np.array([item["target"] for item in data], dtype=np.float32)
    return X, y

def train_perfect_model():
    print("=============================================")
    print("ðŸ† AntivirusAI - PERFECT Scratch Training")
    print("=============================================")
    
    # 1. ×˜×¢×™× ×ª ×”×‘×¡×™×¡ ×©×œ EMBER (×›××Ÿ ×”×•× ×ž×—×¤×© ××ª ×”-.dat)
    print("â³ Loading full EMBER 2018 dataset (Takes a few minutes)...")
    try:
        X_train_ember, y_train_ember, X_test_ember, y_test_ember = ember.read_vectorized_features(EMBER_DIR)
        train_labeled = (y_train_ember != -1)
        X_train_filtered = X_train_ember[train_labeled]
        y_train_filtered = y_train_ember[train_labeled]
        print(f"   âœ… EMBER base loaded: {len(y_train_filtered)} samples.")
    except Exception as e:
        print(f"âŒ Failed to load EMBER: {e}")
        print("   Did you make sure to run 'ember.create_vectorized_features' first?")
        return

    # 2. ×˜×¢×™× ×ª ×”×ª×•×¡×¤×•×ª ×©×œ×š
    print("\nðŸ“¥ Loading modern data...")
    try:
        X_malware, y_malware = load_json_features(MY_BLINDSPOTS)
        print(f"   â˜ ï¸ Loaded {len(y_malware)} modern malware samples (Target 1).")
        
        X_clean, y_clean = load_json_features(MY_CLEAN_FILES)
        print(f"   ðŸ›¡ï¸ Loaded {len(y_clean)} diverse clean software samples (Target 0).")
    except Exception as e:
        print(f"âŒ Failed to load JSON files: {e}")
        return

    # 3. ×ž×™×–×•×’ ×”×¢×•×œ×ž×•×ª
    print("\nðŸ§¬ Merging all datasets...")
    X_train_final = np.vstack((X_train_filtered, X_malware, X_clean))
    y_train_final = np.concatenate((y_train_filtered, y_malware, y_clean))
    print(f"ðŸ“Š Massive Final Training Set Size: {len(y_train_final)} files.")

    test_labeled = (y_test_ember != -1)
    X_test_filtered = X_test_ember[test_labeled]
    y_test_filtered = y_test_ember[test_labeled]

    train_dataset = lgb.Dataset(X_train_final, label=y_train_final)
    valid_dataset = lgb.Dataset(X_test_filtered, label=y_test_filtered, reference=train_dataset)

    # 4. ××™×ž×•×Ÿ
    params = {
        "boosting": "gbdt",
        "objective": "binary",
        "metric": "auc",
        "learning_rate": 0.05,
        "num_leaves": 31,
        "max_depth": -1,
        "verbosity": -1
    }

    print("\nðŸš€ STARTING FULL TRAINING FROM SCRATCH!")
    print("   Please wait, building trees...")
    print("-" * 60)
    
    try:
        model = lgb.train(
            params,
            train_dataset,
            num_boost_round=1000, 
            valid_sets=[train_dataset, valid_dataset],
            callbacks=[
                lgb.log_evaluation(period=50),
                lgb.early_stopping(stopping_rounds=50)
            ]
        )
        
        model.save_model(NEW_MODEL_OUT)
        print("\n=============================================")
        print(f"ðŸ† SUCCESS! The Perfect Bias-Free Model is ready.")
        print(f"ðŸ’¾ Saved to: {NEW_MODEL_OUT}")
        print("=============================================")
        
    except Exception as e:
        print(f"âŒ Training failed: {e}")

if __name__ == "__main__":
    train_perfect_model()
