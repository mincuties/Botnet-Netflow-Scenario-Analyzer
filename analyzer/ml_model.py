"""Optional decision tree (machine learning) layer. Used only with --ml.

This module goes beyond the course guideline of simple algorithms; the
reasons and the measured effect are in README.md (section "Evaluation"). The rest
of the program does not need scikit-learn: it is imported only here, and
only when this layer is switched on.

A decision tree is a list of yes/no questions learned from labelled data,
for example "more than 120 flows in this window?" then "more than 40 %
failed TCP attempts?". Its depth is limited to 4 so the whole tree can be
drawn (docs/results/decision_tree.png) and explained question by question.

Unit of data: one (source IP, 5-minute window), described by the numbers
in windows.FEATURE_NAMES. Label: 1 if that IP sent a From-Botnet flow in
that window. An IP's probability is that of its most suspicious window.
"""

import pickle

from analyzer.windows import FEATURE_NAMES, window_features

MAX_DEPTH = 4
RANDOM_STATE = 0   # fixed, so training twice gives the same tree


def windows_to_rows(windows):
    """Turn {(ip, window): counts} into feature rows X and labels y."""
    keys = sorted(windows)    # fixed order -> reproducible training
    X = [window_features(windows[key]) for key in keys]
    y = [1 if windows[key]["is_bot"] else 0 for key in keys]
    return keys, X, y


def train_tree(X, y):
    """Fit a small decision tree. class_weight="balanced" makes the rare
    bot windows count as much in total as the many normal ones."""
    from sklearn.tree import DecisionTreeClassifier
    tree = DecisionTreeClassifier(max_depth=MAX_DEPTH, class_weight="balanced",
                                  min_samples_leaf=20, random_state=RANDOM_STATE)
    tree.fit(X, y)
    return tree


def save_model(tree, path):
    with open(path, "wb") as file:
        pickle.dump(tree, file)


def load_model(path):
    """Load a trained tree. Raises OSError / pickle errors if unusable."""
    with open(path, "rb") as file:
        return pickle.load(file)


def ip_probabilities(tree, windows):
    """Return {src_ip: highest bot probability over its windows}."""
    if len(windows) == 0:
        return {}
    keys, X, _ = windows_to_rows(windows)
    # predict_proba gives one column per class; column 1 is "bot".
    bot_column = list(tree.classes_).index(1)
    probabilities = tree.predict_proba(X)[:, bot_column]
    best = {}
    for (ip, _), p in zip(keys, probabilities):
        best[ip] = max(best.get(ip, 0.0), float(p))
    return best


def describe_tree(tree):
    """The tree as indented text rules, for the documentation."""
    from sklearn.tree import export_text
    return export_text(tree, feature_names=FEATURE_NAMES, decimals=2)


def plot_tree_png(tree, path):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from sklearn.tree import plot_tree
    fig, ax = plt.subplots(figsize=(18, 8))
    plot_tree(tree, feature_names=FEATURE_NAMES, class_names=["not bot", "bot"],
              filled=True, impurity=False, proportion=True, rounded=True, fontsize=8, ax=ax)
    ax.set_title(f"Decision tree (max depth {MAX_DEPTH}) on 5-minute windows")
    fig.tight_layout()
    fig.savefig(path, dpi=110)
    plt.close(fig)
