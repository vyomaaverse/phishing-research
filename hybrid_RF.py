import pandas as pd
import numpy as np
from sklearn.model_selection import cross_val_predict, cross_val_score, RepeatedStratifiedKFold, StratifiedKFold, cross_validate
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, make_scorer, precision_score, recall_score,f1_score

# Load the data
df = pd.read_csv('features_extracted_01-01-24_dots_path_dots_dom_token.csv')

# Rule-based classification
rule_based_features = ['brand_path', 'brand_subdomain', 'brand_substring_dom','brand_typo_dom', 'fake_tld']
rule_based_mask = df[rule_based_features].sum(axis=1) > 0
df['rule_based_prediction'] = rule_based_mask.astype(int)

# Separate rule-based and machine learning datasets
rule_based_data = df[rule_based_mask].copy()
ml_data = df[~rule_based_mask].copy()

# Rule-based metrics
rule_based_accuracy = accuracy_score(rule_based_data['label'], rule_based_data['rule_based_prediction'])
rule_based_precision = precision_score(rule_based_data['label'], rule_based_data['rule_based_prediction'])
rule_based_recall = recall_score(rule_based_data['label'], rule_based_data['rule_based_prediction'])
rule_based_f1=f1_score(rule_based_data['label'], rule_based_data['rule_based_prediction'])

print("Rule-Based Metrics:")
print(f"Accuracy: {rule_based_accuracy:.4f}")
print(f"Precision: {rule_based_precision:.4f}")
print(f"Recall: {rule_based_recall:.4f}")
print(f"F1 score:{rule_based_f1:.4f}")
rule_based_data.to_csv('rule_results_01-01-24.csv', index=False)
# Machine learning classification with cross-validation

clf = RandomForestClassifier(n_estimators=100, random_state=42)

X = ml_data.drop(['url', 'label'], axis=1)
y = ml_data['label']

# Define the metrics to be calculated during cross-validation
scoring = {'accuracy': 'accuracy', 'precision': 'precision', 'recall': 'recall', 'f1': 'f1'}

# Number of repeats
num_repeats = 10

ml_cv_predictions = []
ml_cv_scores = []
ml_rule_accuracy=[]
ml_rule_precision=[]
ml_rule_recall=[]

for _ in range(num_repeats):
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42) 
    ml_cv_predictions.clear()
    # Perform cross-validation on the entire dataset
    cv_results = cross_val_predict(clf, X, y, cv=cv)
    scores = cross_validate(clf, X, y,  cv=StratifiedKFold(n_splits=5, shuffle=True, random_state=42), scoring=scoring, return_train_score=False)
    ml_cv_predictions.extend(cv_results)


    ml_cv_scores.append(scores)
    ml_rule_predictions= pd.concat([rule_based_data['rule_based_prediction'], pd.Series(ml_cv_predictions)])
    ml_rule_labels=pd.concat([rule_based_data['label'], y])
    ml_rule_accuracy.append(accuracy_score(ml_rule_labels, ml_rule_predictions))
    ml_rule_precision.append(precision_score(ml_rule_labels, ml_rule_predictions))
    ml_rule_recall.append(recall_score(ml_rule_labels, ml_rule_predictions))
    

"""ml_predictions_df = ml_data[['url', 'label']].copy()  # Copy features and actual labels
ml_predictions_df['ml_prediction'] = ml_cv_predictions  # Add machine learning predictions

# Save to CSV file
ml_predictions_df.to_csv('ml_predictions_01-01-24.csv', index=False)"""

# Print test metrics
print(f"Mean Test Accuracy: {np.mean([score['test_accuracy'].mean() for score in ml_cv_scores]):.4f}")
print(f"Mean Test Precision: {np.mean([score['test_precision'].mean() for score in ml_cv_scores]):.4f}")
print(f"Mean Test recall: {np.mean([score['test_recall'].mean() for score in ml_cv_scores]):.4f}")

#print overall metrics
print(f"Overall Accuracy: { (sum(ml_rule_accuracy) / len(ml_rule_accuracy)):.4f}")
print(f"Overall Precision: { (sum(ml_rule_precision) / len(ml_rule_precision)):.4f}")
print(f"Overall Recall: { (sum(ml_rule_recall) / len(ml_rule_recall)):.4f}")





