import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
import joblib
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import os

# × ×ª×™×‘×™×
CSV_PATH = r"C:\Users\omri9\Desktop\School\Final Project\data\datasets\optimized_dataset.csv"
MODEL_PATH = r"C:\Users\omri9\Desktop\School\Final Project\models\ai_antivirus_model.pkl"

def main():
    print("â³ Loading the Optimized Dataset...")
    if not os.path.exists(CSV_PATH):
        print(f"âŒ Error: Cannot find CSV file at {CSV_PATH}")
        return

    df = pd.read_csv(CSV_PATH)
    print(f"ðŸ“Š Dataset size: {len(df):,} rows. Pure quality!")

    # ×ž×—×™×§×ª ×¢×ž×•×“×•×ª ×©×œ× ×¨×œ×•×•× ×˜×™×•×ª ×œ×ž×ª×ž×˜×™×§×” ×©×œ ×”×ž×•×“×œ
    cols_to_drop = ['target', 'file_name', 'md5', 'imphash']
    X = df.drop(columns=[col for col in cols_to_drop if col in df.columns])
    y = df['target']

    # ×—×œ×•×§×” ×œ× ×ª×•× ×™ ××™×ž×•×Ÿ (80%) ×•×ž×‘×—×Ÿ (20%)
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    print("\nðŸ§  Training Random Forest Model... (Should be lightning fast now!)")
    # ××™×Ÿ ×¦×•×¨×š ×™×•×ª×¨ ×‘×”×’×“×¨×•×ª ×ž×©×§×œ ×ž×•×¨×›×‘×•×ª ×›×™ ×”×“××˜×” ×ž××•×–×Ÿ ×ž×¨××©
    model = RandomForestClassifier(n_estimators=100, max_depth=20, n_jobs=-1, random_state=42)
    model.fit(X_train, y_train)

    print("\nâœ… Training complete. Evaluating accuracy...")
    y_pred = model.predict(X_test)
    print(classification_report(y_test, y_pred))

    print(f"\nðŸ’¾ Saving the final ultimate model to: {MODEL_PATH}")
    joblib.dump(model, MODEL_PATH)
    print("ðŸŽ‰ Done! Go run the scanner on Teams!")

if __name__ == "__main__":
    main()
