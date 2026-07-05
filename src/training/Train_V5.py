import json
import numpy as np
import lightgbm as lgb
import ember
import os
from sklearn.utils import shuffle

# --- ×ª×™×§×•× ×™ ×ª××™×ž×•×ª Numpy (×—×•×‘×” ×‘×’×œ×œ ×’×¨×¡××•×ª ×”×¡×¤×¨×™×™×”) ---
if not hasattr(np, 'int'): np.int = int
if not hasattr(np, 'bool'): np.bool = bool
if not hasattr(np, 'float'): np.float = float
if not hasattr(np, 'object'): np.object = object

# ==========================================
# 1. ×”×’×“×¨×ª × ×ª×™×‘×™× (×¢×“×›×Ÿ ×œ× ×ª×™×‘×™× ×©×œ×š)
# ==========================================
EMBER_DIR = r"C:\Users\omri9\Desktop\School\Final Project\data\datasets"
MY_CLEAN_FILES = r"C:\Users\omri9\Desktop\School\Final Project\data\datasets\modern_clean_files.json"
MY_BLINDSPOTS = r"C:\Users\omri9\Desktop\School\Final Project\data\datasets\malware_blindspots_V5.json"# ×”×§×•×‘×¥ ×”×¢× ×§ ×©××¡×¤× ×•
NEW_MODEL_OUT = r"C:\Users\omri9\Desktop\School\Final Project\final\AntivirusAI_V5_Master.txt"

def load_json_to_numpy(filepath):
    """×¤×•× ×§×¦×™×” ×©×˜×•×¢× ×ª JSON ×™×©×™×¨×•×ª ×œ×ž×¢×¨×š Numpy ×“×—×•×¡ ×•×—×¡×›×•× ×™ ×‘×–×™×›×¨×•×Ÿ"""
    print(f"   [+] Loading {os.path.basename(filepath)}...")
    with open(filepath, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    # ×—×™×œ×•×¥ ×ž××¤×™×™× ×™× ×•×ª×•×•×™×•×ª
    X = np.array([item["features"] for item in data], dtype=np.float32)
    y = np.array([item["target"] for item in data], dtype=np.float32)
    return X, y

def merge_and_train():
    print("=============================================")
    print("ðŸ§¬ AntivirusAI - Data Merger & Master Trainer")
    print("=============================================")
    
    # --- ×©×œ×‘ ×': ×˜×¢×™× ×ª ×”× ×ª×•× ×™× ---
    try:
        print("\nâ³ 1. Loading EMBER Base (This takes RAM & Time)...")
        X_ember, y_ember, X_test_ember, y_test_ember = ember.read_vectorized_features(EMBER_DIR)
        
        # ×¡×™× ×•×Ÿ ×§×‘×¦×™× ×œ×œ× ×ª×•×•×™×ª ×‘-EMBER (×ª×•×•×™×ª -1 ×”×™× ×—×¡×¨×ª ×ž×©×ž×¢×•×ª)
        valid_idx = (y_ember != -1)
        X_ember = X_ember[valid_idx]
        y_ember = y_ember[valid_idx]
        
        print("\nðŸ“¥ 2. Loading Custom 2026 Datasets...")
        X_clean, y_clean = load_json_to_numpy(MY_CLEAN_FILES)
        X_mal, y_mal = load_json_to_numpy(MY_BLINDSPOTS)
        
    except Exception as e:
        print(f"âŒ Error loading data: {e}")
        return

    # --- ×©×œ×‘ ×‘': ×ž×™×–×•×’ ×•×”×–×¨×§×ª ×ž×©×§×œ×™× ---
    print("\nâš–ï¸ 3. Merging datasets & Assigning Importance Weights...")
    
    # ×ž×©×§×œ×™×: EMBER ×¨×’×™×œ ×™×§×‘×œ 1.0. ×”×§×‘×¦×™× ×”×—×“×©×™× ×©×œ× ×• ×™×§×‘×œ×• 10.0!
    weights_ember = np.ones(len(y_ember), dtype=np.float32)
    weights_clean = np.full(len(y_clean), 10.0, dtype=np.float32)
    weights_mal = np.full(len(y_mal), 10.0, dtype=np.float32)
    
    # ××™×—×•×“ ×›×œ ×”×˜×‘×œ××•×ª ××—×ª ×ž×ª×—×ª ×œ×©× ×™×™×” (Vertically Stack)
    X_train_merged = np.vstack((X_ember, X_clean, X_mal))
    y_train_merged = np.concatenate((y_ember, y_clean, y_mal))
    weights_merged = np.concatenate((weights_ember, weights_clean, weights_mal))
    
    print(f"   [i] Total Training Samples: {len(y_train_merged)}")
    
    # --- ×©×œ×‘ ×’': ×¢×¨×‘×•×‘ (Shuffling) ---
    print("ðŸ”€ 4. Shuffling the massive dataset...")
    # ×¢×¨×‘×•×‘ ×—×›× ×©×©×•×ž×¨ ×¢×œ ×”×§×©×¨ ×‘×™×Ÿ ×”×ž××¤×™×™×Ÿ, ×”×ª×•×•×™×ª ×•×”×ž×©×§×œ ×©×œ×•
    X_train_shuffled, y_train_shuffled, weights_shuffled = shuffle(
        X_train_merged, y_train_merged, weights_merged, random_state=42
    )

    # ×”×›× ×ª ×§×‘×•×¦×ª ×”×‘×“×™×§×” (20% ×ž-EMBER ×©×œ× × ×’×¢× ×• ×‘×”×)
    test_idx = (y_test_ember != -1)
    X_val = X_test_ember[test_idx]
    y_val = y_test_ember[test_idx]

    # ×™×¦×™×¨×ª ××•×‘×™×™×§×˜×™× ×™×™×¢×•×“×™×™× ×©×œ LightGBM (×©×¦×•×¨×›×™× ×”×›×™ ×ž×¢×˜ ×–×™×›×¨×•×Ÿ)
    train_data = lgb.Dataset(X_train_shuffled, label=y_train_shuffled, weight=weights_shuffled)
    valid_data = lgb.Dataset(X_val, label=y_val, reference=train_data)

    # --- ×©×œ×‘ ×“': ××™×ž×•×Ÿ ×ž×¤×œ×¦×ª ---
    params = {
        "boosting": "gbdt",
        "objective": "binary",
        "metric": "auc",
        "learning_rate": 0.05,
        "num_leaves": 31,
        "max_depth": -1,
        "verbosity": -1,
        "tree_learner": "serial"
    }

    print("\nðŸš€ 5. STARTING MASTER TRAINING (Trees: 1000)")
    print("-" * 50)
    
    try:
        model = lgb.train(
            params,
            train_data,
            num_boost_round=1000, 
            valid_sets=[train_data, valid_data],
            callbacks=[
                lgb.log_evaluation(period=50),
                lgb.early_stopping(stopping_rounds=50)
            ]
        )
        
        # --- ×©×œ×‘ ×”': ×©×ž×™×¨×” ---
        model.save_model(NEW_MODEL_OUT)
        print("\n=============================================")
        print(f"ðŸ† SUCCESS! Master V5 Model trained and saved.")
        print(f"ðŸ’¾ File: {NEW_MODEL_OUT}")
        print("=============================================")
        
    except Exception as e:
        print(f"âŒ Training Failed: {e}")

if __name__ == "__main__":
    merge_and_train()
