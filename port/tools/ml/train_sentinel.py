#!/usr/bin/env python3
"""
StockFW Neural Sentinel: Offline TinyML Model Trainer & C Header Exporter
Trains a lightweight gradient-boosted decision tree ensemble on simulated host-window
network features (FsHit event stream aggregations) and exports pure integer C arrays
and threshold comparison rules to port/src/core/fs-ml-model.h.
"""

import os
import sys
import numpy as np

try:
    from sklearn.ensemble import GradientBoostingClassifier
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import classification_report, f1_score
except ImportError:
    print("Installing scikit-learn and numpy for offline training...", file=sys.stderr)
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "scikit-learn", "numpy"])
    from sklearn.ensemble import GradientBoostingClassifier
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import classification_report, f1_score

# Feature definitions corresponding to FsMlHostFeatures
FEATURE_NAMES = [
    "event_rate",         # events per sliding window
    "burst_ratio",        # max burst vs average rate
    "distinct_ports",     # number of unique destination ports
    "distinct_peers",     # number of unique remote IP addresses
    "tcp_ratio",          # fraction of TCP events
    "udp_ratio",          # fraction of UDP events
    "length_mean",        # average packet length
    "length_std",         # standard deviation of packet lengths
    "beacon_regularity",  # inter-arrival time coefficient of variation (inverse)
    "login_port_frac",    # fraction of traffic hitting ports 22, 3389, 445, etc.
    "block_ratio",        # fraction of events that were blocked
    "threat_intel_frac",  # fraction hitting threat intel rules
    "hour_of_day"         # 0 - 23 normalized
]

def generate_synthetic_dataset(n_samples=5000):
    np.random.seed(42)
    X = []
    y = []

    for _ in range(n_samples):
        # Class 0: NORMAL
        # Moderate event rate, low distinct ports/peers, normal length, low login port hit
        rate = np.random.exponential(5.0)
        burst = np.random.uniform(1.1, 2.5)
        ports = np.random.poisson(2.0) + 1
        peers = np.random.poisson(1.5) + 1
        tcp = np.random.uniform(0.6, 0.95)
        udp = 1.0 - tcp
        l_mean = np.random.normal(500, 150)
        l_std = np.random.normal(100, 30)
        beacon = np.random.uniform(0.0, 0.3)
        login_f = np.random.uniform(0.0, 0.05)
        block_f = np.random.uniform(0.0, 0.02)
        ti_f = 0.0
        hour = np.random.randint(0, 24)

        # Introduce classes based on behavioral signatures
        r = np.random.rand()
        if r < 0.15:
            # SCAN: high event rate, high distinct ports, low peers or high peers
            class_label = 1 # SCAN
            rate = np.random.uniform(40.0, 200.0)
            burst = np.random.uniform(4.0, 10.0)
            ports = np.random.randint(15, 100)
            block_f = np.random.uniform(0.3, 0.9)
        elif r < 0.25:
            # BRUTE: high hit rate on login ports (22, 3389, 445)
            class_label = 2 # BRUTE
            rate = np.random.uniform(15.0, 80.0)
            login_f = np.random.uniform(0.6, 1.0)
            ports = np.random.randint(1, 3)
            block_f = np.random.uniform(0.1, 0.5)
        elif r < 0.35:
            # BEACON: high beacon regularity (low jitter), low distinct ports, fixed interval
            class_label = 3 # BEACON
            beacon = np.random.uniform(0.75, 0.99)
            ports = 1
            peers = 1
            rate = np.random.uniform(1.0, 4.0)
        else:
            class_label = 0 # NORMAL

        X.append([
            min(255, max(0, rate * 2.0)),
            min(255, max(0, burst * 25.0)),
            min(255, max(0, ports * 2.5)),
            min(255, max(0, peers * 5.0)),
            min(255, max(0, tcp * 255.0)),
            min(255, max(0, udp * 255.0)),
            min(255, max(0, l_mean * 0.2)),
            min(255, max(0, l_std * 0.5)),
            min(255, max(0, beacon * 255.0)),
            min(255, max(0, login_f * 255.0)),
            min(255, max(0, block_f * 255.0)),
            min(255, max(0, ti_f * 255.0)),
            min(255, max(0, hour * 10.0))
        ])
        y.append(class_label)

    return np.array(X, dtype=np.float32), np.array(y, dtype=np.int32)

def train_and_export():
    print("Generating synthetic network behavior dataset...")
    X, y = generate_synthetic_dataset(8000)

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    print("Training Gradient Boosting Classifier (n_estimators=16, max_depth=3)...")
    clf = GradientBoostingClassifier(n_estimators=16, max_depth=3, random_state=42, learning_rate=0.1)
    clf.fit(X_train, y_train)

    preds = clf.predict(X_test)
    f1 = f1_score(y_test, preds, average='weighted')
    print(f"Model trained successfully. Weighted F1 Score on test set: {f1:.4f}")
    print(classification_report(y_test, preds, target_names=["NORMAL", "SCAN", "BRUTE", "BEACON"]))

    # Export to C Header
    header_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../port/src/core/fs-ml-model.h"))
    os.makedirs(os.path.dirname(header_path), exist_ok=True)

    with open(header_path, "w") as f:
        f.write("/*--[ fs-ml-model.h ]----------------------------------------------------\n")
        f.write(f" * Neural Sentinel: Auto-generated INT8 GBDT Model Header\n")
        f.write(f" * Test F1 Score: {f1:.4f} (Trained offline on synthetic host behavior windows)\n")
        f.write(" *--------------------------------------------------------------------*/\n")
        f.write("#ifndef FS_ML_MODEL_H\n")
        f.write("#define FS_ML_MODEL_H\n\n")
        f.write("#include <glib.h>\n\n")
        f.write(f"#define FS_ML_N_ESTIMATORS {len(clf.estimators_)}\n")
        f.write(f"#define FS_ML_N_CLASSES {len(clf.classes_)}\n\n")

        # Export estimators (trees)
        # In sklearn GBRT for multiclass, clf.estimators_ is a 2D array of shape (n_estimators, n_classes)
        f.write("typedef struct {\n")
        f.write("    gint   feature_idx;\n")
        f.write("    gint16 threshold;\n")
        f.write("    gint   left_child;\n")
        f.write("    gint   right_child;\n")
        f.write("    gint16 value;\n")
        f.write("} FsMlTreeNode;\n\n")

        # For simplicity and robustness in pure C without dynamic memory allocation for trees,
        # we can flatten tree structures or output a direct evaluation function.
        # Let's write a clean exported evaluator function directly into the header or static arrays.
        f.write("static inline gint\nfs_ml_evaluate_tree_ensemble (const gint8 *x)\n{\n")
        f.write("    /* Integer-quantized multi-class logit accumulation */\n")
        f.write("    gint logits[4] = {0, 0, 0, 0};\n\n")

        # Extract direct decision rules from the fitted trees
        for class_idx, estimators in enumerate(clf.estimators_):
            for tree_idx, tree_estimator in enumerate(estimators):
                tree = tree_estimator.tree_
                # Walk tree and emit if-statements
                f.write(f"    /* Tree {tree_idx} for class {class_idx} */\n")

                def recurse(node_id, depth=0):
                    indent = "    " * (depth + 1)
                    if tree.children_left[node_id] == tree.children_right[node_id]:
                        # Leaf node
                        val = int(tree.value[node_id][0][0] * 100)
                        return f"{indent}logits[{class_idx}] += {val};\n"
                    else:
                        feat = int(tree.feature[node_id])
                        thresh = int(tree.threshold[node_id] * 10)
                        left = tree.children_left[node_id]
                        right = tree.children_right[node_id]

                        code = f"{indent}if (x[{feat}] <= {thresh}) {{\n"
                        code += recurse(left, depth + 1)
                        code += f"{indent}}} else {{\n"
                        code += recurse(right, depth + 1)
                        code += f"{indent}}}\n"
                        return code

                f.write(recurse(0))

        f.write("\n    /* Argmax over logits */\n")
        f.write("    gint max_logit = logits[0];\n")
        f.write("    gint best_class = 0;\n")
        f.write("    for (gint c = 1; c < 4; c++) {\n")
        f.write("        if (logits[c] > max_logit) {\n")
        f.write("            max_logit = logits[c];\n")
        f.write("            best_class = c;\n")
        f.write("        }\n")
        f.write("    }\n")
        f.write("    return best_class;\n")
        f.write("}\n\n")
        f.write("#endif /* FS_ML_MODEL_H */\n")

    print(f"Model successfully exported to {header_path}")

if __name__ == "__main__":
    train_and_export()
