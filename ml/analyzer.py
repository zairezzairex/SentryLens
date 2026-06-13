import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder, StandardScaler


def analyze_threats(filepath):
    """
    Analyze insider threats using Isolation Forest algorithm.
    Returns structured results for dashboard visualization.
    """
    df = pd.read_csv(filepath)
    df.columns = [c.strip().lower().replace(' ', '_') for c in df.columns]

    # Identify numeric and categorical columns
    numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
    categorical_cols = df.select_dtypes(include=['object']).columns.tolist()

    # Encode categoricals
    le = LabelEncoder()
    df_encoded = df.copy()
    for col in categorical_cols:
        try:
            df_encoded[col] = le.fit_transform(df[col].astype(str))
        except Exception:
            df_encoded.drop(columns=[col], inplace=True)

    # Drop non-informative ID-like columns
    id_like = [c for c in df_encoded.columns if 'id' in c or 'name' in c or 'email' in c]
    df_model = df_encoded.drop(columns=id_like, errors='ignore')

    # Scale
    scaler = StandardScaler()
    X = scaler.fit_transform(df_model.fillna(0))

    # Isolation Forest
    iso = IsolationForest(contamination=0.15, random_state=42, n_estimators=150)
    predictions = iso.fit_predict(X)
    scores = iso.decision_function(X)

    # -1 = anomaly (high risk), 1 = normal (low risk)
    df['risk_label'] = ['High Risk' if p == -1 else 'Low Risk' for p in predictions]
    df['anomaly_score'] = scores

    high_risk_count = int((predictions == -1).sum())
    low_risk_count = int((predictions == 1).sum())
    total = len(df)

    # Risk distribution by categorical columns (for bar/pie charts)
    dept_col = next((c for c in df.columns if 'dept' in c or 'department' in c or 'team' in c or 'role' in c), None)
    dept_breakdown = {}
    if dept_col:
        grp = df.groupby(dept_col)['risk_label'].value_counts().unstack(fill_value=0)
        dept_breakdown = grp.reset_index().to_dict(orient='records')

    # Score distribution for histogram
    score_bins = np.histogram(scores, bins=10)
    score_hist = {
        'counts': score_bins[0].tolist(),
        'edges': [round(e, 3) for e in score_bins[1].tolist()]
    }

    # Top high risk records
    high_risk_df = df[df['risk_label'] == 'High Risk'].copy()
    high_risk_df = high_risk_df.sort_values('anomaly_score').head(10)
    top_threats = high_risk_df.drop(columns=['anomaly_score']).fillna('N/A').to_dict(orient='records')

    # Monthly/time trend if date column exists
    date_col = next((c for c in df.columns if 'date' in c or 'time' in c or 'month' in c or 'day' in c), None)
    time_trend = []
    if date_col:
        try:
            df['_parsed_date'] = pd.to_datetime(df[date_col], errors='coerce')
            df['_month'] = df['_parsed_date'].dt.to_period('M').astype(str)
            trend = df.groupby(['_month', 'risk_label']).size().unstack(fill_value=0).reset_index()
            time_trend = trend.to_dict(orient='records')
        except Exception:
            pass

    # Column names for display
    all_columns = [c for c in df.columns if c not in ['anomaly_score', '_parsed_date', '_month']]

    return {
        'summary': {
            'total': total,
            'high_risk': high_risk_count,
            'low_risk': low_risk_count,
            'high_risk_pct': round(high_risk_count / total * 100, 1),
            'low_risk_pct': round(low_risk_count / total * 100, 1),
        },
        'dept_breakdown': dept_breakdown,
        'dept_col': dept_col,
        'score_histogram': score_hist,
        'top_threats': top_threats,
        'time_trend': time_trend,
        'columns': all_columns,
    }
