import time
import numpy as np
import pandas as pd
import os
import sys

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from sklearn.preprocessing import StandardScaler
from pyod.models.knn import KNN
from pyod.models.iforest import IForest
from pyod.models.hbos import HBOS

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

sc = StandardScaler()
X_tr_sc = sc.fit_transform(X_tr.values)
X_te_sc = sc.transform(X_te.values)

np.random.seed(11)
idx = np.random.choice(len(X_tr_sc), size=10000, replace=False)
X_sub = X_tr_sc[idx]

knn = KNN(n_neighbors=5, n_jobs=1).fit(X_sub)
ifo = IForest(n_estimators=100, random_state=11, n_jobs=1).fit(X_tr_sc)
hbos = HBOS(n_bins=20).fit(X_tr_sc)

print("Timing KNN alone (5 passes on 22,544 test records):")
knn_times = []
for i in range(5):
    t0 = time.perf_counter()
    _ = knn.decision_function(X_te_sc)
    dt = time.perf_counter() - t0
    lat = (dt / len(X_te_sc)) * 1e6
    knn_times.append(lat)
    print(f"  KNN Pass {i+1}: {dt:.3f}s -> {lat:.2f} ms/1k")

print("\nTiming Fusion (5 passes):")
fusion_times = []
for i in range(5):
    t0 = time.perf_counter()
    s1 = ifo.decision_function(X_te_sc)
    s2 = hbos.decision_function(X_te_sc)
    s3 = knn.decision_function(X_te_sc)
    dt = time.perf_counter() - t0
    lat = (dt / len(X_te_sc)) * 1e6
    fusion_times.append(lat)
    print(f"  Fusion Pass {i+1}: {dt:.3f}s -> {lat:.2f} ms/1k")

print("\nTiming Individual components inside a single pass:")
t0 = time.perf_counter()
s1 = ifo.decision_function(X_te_sc)
t_ifo = time.perf_counter() - t0

t0 = time.perf_counter()
s2 = hbos.decision_function(X_te_sc)
t_hbos = time.perf_counter() - t0

t0 = time.perf_counter()
s3 = knn.decision_function(X_te_sc)
t_knn = time.perf_counter() - t0

print(f"  IForest: {t_ifo:.3f}s ({(t_ifo/len(X_te_sc))*1e6:.2f} ms/1k)")
print(f"  HBOS:    {t_hbos:.3f}s ({(t_hbos/len(X_te_sc))*1e6:.2f} ms/1k)")
print(f"  KNN:     {t_knn:.3f}s ({(t_knn/len(X_te_sc))*1e6:.2f} ms/1k)")
print(f"  Sum:     {t_ifo+t_hbos+t_knn:.3f}s ({((t_ifo+t_hbos+t_knn)/len(X_te_sc))*1e6:.2f} ms/1k)")

