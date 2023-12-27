import pandas as pd
import numpy as np
from sklearn.model_selection import cross_val_predict, cross_val_score, RepeatedStratifiedKFold, StratifiedKFold, cross_validate
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, make_scorer, precision_score, recall_score,f1_score

# Load the data
df = pd.read_csv('first5000.csv')

# Rule-based classification
rule_based_features = ['brand_path', 'brand_subdomain', 'brand_substring_dom', 'brand_typo_dom', 'fake_tld']
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

# Machine learning classification with cross-validation
X = ml_data.drop(['url', 'label'], axis=1)
y = ml_data['label']

clf = RandomForestClassifier(n_estimators=100, random_state=42)
# print(y.value_counts())
# cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
scoring = {'accuracy' : 'accuracy','precision': 'precision', 'recall': 'recall'}

# Initialize the cross-validation method
rskf = RepeatedStratifiedKFold(n_splits=5, n_repeats=10, random_state=42)

# Initialize arrays to hold the predictions and true labels
all_predictions = []

# Manually implement the cross-validation loop
for train_index, test_index in rskf.split(X, y):
    X_train, X_test = X.iloc[train_index], X.iloc[test_index]
    y_train, y_test = y.iloc[train_index], y.iloc[test_index]
    
    # Fit the classifier and make predictions
    clf.fit(X_train, y_train)
    predictions = clf.predict(X_test)
    
    # Store the predictions and true labels
    all_predictions.extend(predictions)

all_predictions = np.array(all_predictions)
all_predictions = all_predictions.reshape((-1, len(X)))
average_predictions = all_predictions.mean(axis=0)

cv_results = pd.Series(average_predictions, index=X.index)

threshold = 0.5
cv_results = (cv_results > threshold).astype(int)

ml_cv_scores = cross_validate(clf, X, y, cv=rskf, scoring=scoring, return_train_score=True)

rule_based_data.to_csv('rule_results.csv', index=False)

# Extract and print the cross-validation results
print("Machine Learning Metrics:")
print("Mean Training Accuracy: {:.3f}".format(np.mean(ml_cv_scores['test_accuracy'])))
print("Mean Training Precision: {:.3f}".format(np.mean(ml_cv_scores['test_precision'])))
print("Mean Training Recall: {:.3f}".format(np.mean(ml_cv_scores['test_recall'])))

# Overall metrics (combining rule-based and machine learning predictions)
overall_predictions = pd.concat([rule_based_data['rule_based_prediction'], cv_results])
overall_labels = pd.concat([rule_based_data['label'], y])

overall_accuracy = accuracy_score(overall_labels, overall_predictions)
overall_precision = precision_score(overall_labels, overall_predictions)
overall_recall = recall_score(overall_labels, overall_predictions)
overall_f1=f1_score(overall_labels, overall_predictions)

print("\nOverall Metrics:")
print(f"Overall Accuracy: {overall_accuracy:.4f}")
print(f"Overall Precision: {overall_precision:.4f}")
print(f"Overall Recall: {overall_recall:.4f}")
print(f"f1_score:{overall_f1:.4f}")