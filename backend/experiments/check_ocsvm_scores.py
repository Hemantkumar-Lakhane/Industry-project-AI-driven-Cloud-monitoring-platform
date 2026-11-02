import os
import sys
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from pyod.models.ocsvm import OCSVM

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(ROOT_DIR, "data")
FLOW_FEATURES = ["duration", "src_bytes", "dst_bytes", "count", "srv_count", "serror_rate", "rerror_rate", "same_srv_rate", "diff_srv_rate"]
BYTE_COLS = ["duration", "src_bytes", "dst_bytes", "count", "srv_count"]
KDD_COLUMNS = ["duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes", "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in", "num_compromised", "root_shell", "su_attempted", "num_root", "num_file_creations", "num_shells", "num_access_files", "num_outbound_cmds", "is_host_login", "is_guest_login", "count", "srv_count", "serror_rate", "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count", "dst_host_same_srv_rate", "dst_host_diff_srv_rate", "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate", "dst_host_rerror_rate", "dst_host_srv_rerror_rate", "label", "difficulty"]

df_train = pd.read_csv(os.path.join(DATA_DIR, "KDDTrain+.txt"), header=None, names=KDD_COLUMNS)
df_test = pd.read_csv(os.path.join(DATA_DIR, "KDDTest+.txt"), header=None, names=KDD_COLUMNS)
norm = df_train[df_train["label"].str.strip().str.lower() == "normal"]

X_tr = norm[FLOW_FEATURES].copy()
X_te = df_test[FLOW_FEATURES].copy()
for c in BYTE_COLS:
    X_tr[c] = np.log1p(X_tr[c].astype(float))
    X_te[c] = np.log1p(X_te[c].astype(float))

for seed in [11, 23, 37, 51, 73]:
    tr, val = train_test_split(norm, test_size=0.20, random_state=seed)
    X_fit = tr[FLOW_FEATURES].copy()
    for c in BYTE_COLS:
        X_fit[c] = np.log1p(X_fit[c].astype(float))
    sc = StandardScaler()
    X_fit_sc = sc.fit_transform(X_fit.values)
    X_te_sc = sc.transform(X_te.values)
    
    np.random.seed(seed)
    idx = np.random.choice(len(X_fit_sc), size=10000, replace=False)
    sub = X_fit_sc[idx]
    
    ocsvm = OCSVM(kernel="rbf", gamma="scale").fit(sub)
    scores = ocsvm.decision_function(X_te_sc)
    
    print(f"Seed {seed:2d}: Min score = {np.min(scores):.4f} | Max score = {np.max(scores):.4f} | Plateau (>=1395) = {np.sum(scores >= 1395)} ({np.mean(scores >= 1395)*100:.2f}%)")

