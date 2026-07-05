import json
import numpy as np
import lightgbm as lgb
import ember
import os
from sklearn.model_selection import train_test_split
from sklearn.utils import shuffle

# --- Monkey Patching ---
import lief
for missing_attr in ['bad_format', 'bad_file', 'pe_error', 'parser_error', 'read_out_of_bound', 'not_found']:
    if not hasattr(lief, missing_attr):
        setattr(lief, missing_attr, type(missing_attr, (Exception,), {}))

if not hasattr(np, 'int'): np.int = int
if not hasattr(np, 'bool'): np.bool = bool
if not hasattr(np, 'float'): np.float = float
if not hasattr(np, 'object'): np.object = object
# -------------------------------------------------------------

# ==========================================
# × ×ª×™×‘×™×
# ==========================================
EMBER_DIR = r"C:\Users\omri9\Desktop\School\Final Project\data\datasets"
MY_CLEAN_FILES = r"C:\Users\omri9\Desktop\School\Final Project\data\datasets\modern_clean_files.json"
MY_BLINDSPOTS = r"C:\Users\omri9\Desktop\School\Final Project\data\datasets\malware_blindspots_V5.json"
NEW_MODEL_OUT = r"C:\Users\omri9\Desktop\School\Final Project\final\AntivirusAI_V6_Balanced.txt"

def load_json_to_numpy(filepath):
    print(f"   [+] Loading {os.path.basename(filepath)}...")
    with open(filepath, 'r', encoding='utf-8') as f:
        data = json.load(f)
    X = np.array([item["features"] for item in data], dtype=np.float32)
    y = np.array([item["target"] for item in data], dtype=np.float32)
    return X, y

def train_balanced_model():
    print("====================================================")
    print("ðŸ§¬ AntivirusAI - Balanced Master Training (V6)")
    print("====================================================")
    
    # 1. ×˜×¢×™× ×ª × ×ª×•× ×™×
    print("\nâ³ 1. Loading Datasets...")
    X_ember, y_ember, X_test_ember, y_test_ember = ember.read_vectorized_features(EMBER_DIR)
    
    # ×¡×™× ×•×Ÿ ×§×‘×¦×™× ×œ×œ× ×ª×•×•×™×ª ×‘-EMBER
    valid_train = (y_ember != -1)
    X_ember = X_ember[valid_train]
    y_ember = y_ember[valid_train]
    
    valid_test = (y_test_ember != -1)
    X_test_ember = X_test_ember[valid_test]
    y_test_ember = y_test_ember[valid_test]

    X_clean, y_clean = load_json_to_numpy(MY_CLEAN_FILES)
    X_mal, y_mal = load_json_to_numpy(MY_BLINDSPOTS)
    
    # 2. ×”×–×¨×§×ª ×”× ×ª×•× ×™× ×”×—×“×©×™× ×œ×¡×˜ ×”×‘×“×™×§×” (20% ×‘×“×™×§×”, 80% ××™×ž×•×Ÿ) - ×–×” ×”×©×“×¨×•×’ ×”×§×¨×™×˜×™!
    print("\nðŸ”ª 2. Splitting 2026 data into Train and Validation sets...")
    Xc_train, Xc_val, yc_train, yc_val = train_test_split(X_clean, y_clean, test_size=0.2, random_state=42)
    Xm_train, Xm_val, ym_train, ym_val = train_test_split(X_mal, y_mal, test_size=0.2, random_state=42)

    # 3. ×‘× ×™×™×ª ×ž××’×¨×™ ×”×¢× ×§
    print("ðŸ—ï¸ 3. Building Master Train & Validation Sets...")
    X_train_merged = np.vstack((X_ember, Xc_train, Xm_train))
    y_train_merged = np.concatenate((y_ember, yc_train, ym_train))
    
    # ×¢×›×©×™×• ×§×‘×•×¦×ª ×”×‘×“×™×§×” (Validation) ×ž×›×™×œ×” ×’× × ×ª×•× ×™× ×ž×©× ×ª 2026!
    X_val_merged = np.vstack((X_test_ember, Xc_val, Xm_val))
    y_val_merged = np.concatenate((y_test_ember, yc_val, ym_val))

    # 4. ×ž×©×§×œ×™× ×ž××•×–× ×™× (×œ× ×’×‘×•×”×™× ×ž×“×™ ×›×“×™ ×œ×ž× ×•×¢ Overfitting)
    # × ×™×ª×Ÿ ×œ× ×ª×•× ×™× ×”×—×“×©×™× ×ž×©×§×œ ×©×œ 5.0. ×–×” "×“×•×—×£" ××ª ×”×ž×•×“×œ ×œ×”×ª×™×™×—×¡ ××œ×™×”×, ×‘×œ×™ ×œ×©×‘×•×¨ ××•×ª×•.
    w_ember = np.ones(len(y_ember), dtype=np.float32)
    w_clean = np.full(len(yc_train), 5.0, dtype=np.float32)
    w_mal = np.full(len(ym_train), 5.0, dtype=np.float32)
    weights_train = np.concatenate((w_ember, w_clean, w_mal))
    
    # 5. ×¢×¨×‘×•×‘
    print("ðŸ”€ 4. Shuffling data...")
    X_train_shuf, y_train_shuf, w_train_shuf = shuffle(X_train_merged, y_train_merged, weights_train, random_state=42)

    train_data = lgb.Dataset(X_train_shuf, label=y_train_shuf, weight=w_train_shuf)
    valid_data = lgb.Dataset(X_val_merged, label=y_val_merged, reference=train_data)

    # 6. ×¤×¨×ž×˜×¨×™× ×—×›×ž×™× × ×’×“ ×©×™× ×•×Ÿ (Anti-Overfitting Hyperparameters)
    params = {
        "boosting": "gbdt",
        "objective": "binary",
        "metric": "auc",
        "learning_rate": 0.05,
        "num_leaves": 64,          # ×œ××¤×©×¨ ×¢×¦×™ ×”×—×œ×˜×” ×§×¦×ª ×™×•×ª×¨ ×ž×•×¨×›×‘×™×
        "max_depth": 10,           # ××‘×œ ×œ×”×’×‘×™×œ ××ª ×”×¢×•×ž×§ ×›×“×™ ×©×œ× ×™×©× ×Ÿ ×§×‘×¦×™× ×¡×¤×¦×™×¤×™×™×
        "min_data_in_leaf": 100,   # ×—×•×‘×” ×œ×¤×—×•×ª 100 ×“×•×’×ž××•×ª ×‘×›×œ ×¢×œ×” (×ž×•× ×¢ Overfitting ×¢×œ ×”×—×•×ž×¨ ×©×œ×š)
        "feature_fraction": 0.8,   # ×‘×—×™×¨×ª ×ž××¤×™×™× ×™× ××§×¨××™×ª
        "bagging_fraction": 0.8,   # ×‘×—×™×¨×ª ×“×•×’×ž××•×ª ××§×¨××™×ª
        "bagging_freq": 1,
        "verbosity": -1,
        "tree_learner": "serial"
    }

    print("\nðŸš€ 5. STARTING ADVANCED TRAINING...")
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
        
        model.save_model(NEW_MODEL_OUT)
        print("\n====================================================")
        print(f"ðŸ† SUCCESS! V6 Balanced Model trained and saved.")
        print(f"ðŸ’¾ File: {NEW_MODEL_OUT}")
        print("====================================================")
        
    except Exception as e:
        print(f"âŒ Training Failed: {e}")

if __name__ == "__main__":
    train_balanced_model()
