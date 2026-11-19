"""The trained classifier: features -> verdict (real / noise / false positive).

Needs scikit-learn (`pip install -e ".[ml]"`). The pipeline is one-hot encoding of
the string features (DictVectorizer) followed by a decision tree of depth 4. A
shallow tree reads like a list of if/else rules: `rules_text()` prints the whole tree
and `explain()` lists the conditions that led to one verdict.

An alert type the model never saw in training is left to the rules. Without this the
tree generalized "a missing header on a file is noise" to every alert on a file and hid
a leaked wp-config.bak in bWAPP, a type that none of the development apps had.

The tree was chosen with `compare()`: leave-one-app-out on the development apps
(train on all of them but one, test on the one left out). Apps in TEST_APPS are kept
out of that choice and out of training. `evaluate()` scores the frozen model on them
once, which is the number we report.
"""

from __future__ import annotations
from collections import Counter
from collections.abc import Callable
from itertools import pairwise
from dataclasses import dataclass, field
from pathlib import Path
from alert_scanner.domain import Finding, Instance, Verdict
from alert_scanner.ml import features
from alert_scanner.ml.dataset import LabeledSample, Sample
from alert_scanner.risk_rules import classify as rule_classify

DEFAULT_MODEL_PATH = Path("models/classifier.joblib")
# Never used to choose the model or the features, never trained on.
TEST_APPS = frozenset({"bwapp"})


class MlClassifier:
    """Drop-in for risk_rules.classify_with_reason: finding -> (verdict, reason).

    A finding is classified by its instances; the finding gets the most cautious
    verdict among them (real before noise before false positive).
    """

    def __init__(self, pipeline, app: str = "scan", mode: str = "full") -> None:
        self._pipeline = pipeline
        self._app = app
        self._mode = mode
        # One-hot columns exist only for the rule ids seen in training.
        names = pipeline.named_steps["features"].get_feature_names_out()
        self.known_rules = frozenset(name.split("=", 1)[1] for name in names if name.startswith("rule_id="))

    @classmethod
    def load(cls, path: str | Path = DEFAULT_MODEL_PATH, **kwargs) -> MlClassifier:
        import joblib

        return cls(joblib.load(path), **kwargs)

    def save(self, path: str | Path = DEFAULT_MODEL_PATH) -> Path:
        import joblib

        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self._pipeline, path)
        return path

    def classify_with_reason(self, finding: Finding) -> tuple[Verdict, str]:
        if finding.rule_id not in self.known_rules:
            return rule_classify(finding), "rules: the model has not seen this alert type"
        instances = finding.instances or (Instance(finding.location, finding.attack, finding.evidence),)
        scored = [(self.classify_instance(finding, instance), instance) for instance in instances]
        (verdict, probability), instance = min(scored, key=lambda item: (int(item[0][0]), -item[0][1]))
        path = " -> ".join(self.explain(Sample(self._app, self._mode, finding, instance)))
        return verdict, f"model: {verdict.label} ({probability:.0%}): {path}"

    def classify(self, finding: Finding) -> Verdict:
        return self.classify_with_reason(finding)[0]

    def classify_instance(self, finding: Finding, instance: Instance) -> tuple[Verdict, float]:
        """Verdict and the share of training samples in the same leaf that had it."""
        if finding.rule_id not in self.known_rules:
            return rule_classify(finding), 1.0
        sample = Sample(self._app, self._mode, finding, instance)
        probabilities = self._pipeline.predict_proba([features.extract(sample)])[0]
        best = max(range(len(probabilities)), key=probabilities.__getitem__)
        return Verdict(int(self._pipeline.classes_[best])), float(probabilities[best])

    def explain(self, sample: Sample) -> list[str]:
        """The conditions on the path from the root of the tree to this sample's leaf."""
        vectorizer, tree = self._pipeline.named_steps["features"], self._pipeline.named_steps["model"]
        row = vectorizer.transform([features.extract(sample)])
        names = vectorizer.get_feature_names_out()
        nodes = tree.decision_path(row).indices
        structure = tree.tree_
        conditions = []
        for node, next_node in pairwise(nodes):
            went_right = next_node == structure.children_right[node]
            conditions.append(_condition(names[structure.feature[node]], structure.threshold[node], went_right))
        return conditions

    def rules_text(self) -> str:
        """The whole tree as indented if/else rules."""
        from sklearn.tree import export_text

        vectorizer, tree = self._pipeline.named_steps["features"], self._pipeline.named_steps["model"]
        class_names = [Verdict(int(value)).label for value in tree.classes_]
        return export_text(tree, feature_names=list(vectorizer.get_feature_names_out()),
                           class_names=class_names, decimals=1)


def train(labeled: list[LabeledSample], test_apps: frozenset[str] = TEST_APPS) -> MlClassifier:
    """Fit on the development apps only, so the shipped model is the one evaluate() scores."""
    return MlClassifier(_fit([item for item in labeled if item.sample.app not in test_apps]))


def evaluate(labeled: list[LabeledSample], test_apps: frozenset[str] = TEST_APPS,
             make_model: Callable | None = None) -> Evaluation:
    """Leave-one-app-out on the development apps, then the final test on `test_apps`.

    The rules are scored on the same rows, so the two columns compare like with like.
    """
    make_model = make_model or _decision_tree
    development = [item for item in labeled if item.sample.app not in test_apps]
    test = [item for item in labeled if item.sample.app in test_apps]
    apps = sorted({item.sample.app for item in development})
    if len(apps) < 2:
        raise ValueError("Leave-one-app-out needs labels from at least two development apps.")

    cross_model, cross_rules = Scores(), Scores()
    for held_out in apps:
        classifier = MlClassifier(_fit([i for i in development if i.sample.app != held_out], make_model))
        _score(classifier, [i for i in development if i.sample.app == held_out], cross_model, cross_rules)

    final_model, final_rules = Scores(), Scores()
    if test:
        _score(MlClassifier(_fit(development, make_model)), test, final_model, final_rules)
    return Evaluation(apps, cross_model, cross_rules, sorted({i.sample.app for i in test}),
                      final_model, final_rules)


def compare(labeled: list[LabeledSample], test_apps: frozenset[str] = TEST_APPS) -> str:
    """Leave-one-app-out for every candidate model, on the development apps only."""
    lines = [f"{'model':<26}{'accuracy':>10}{'macro F1':>10}"]
    rules_written = False
    for name, make_model in CANDIDATES.items():
        evaluation = evaluate([i for i in labeled if i.sample.app not in test_apps], frozenset(), make_model)
        if not rules_written:
            lines.append(f"{'rules (baseline)':<26}{evaluation.rules.accuracy():>10.0%}"
                         f"{evaluation.rules.macro_f1():>10.2f}")
            rules_written = True
        lines.append(f"{name:<26}{evaluation.model.accuracy():>10.0%}{evaluation.model.macro_f1():>10.2f}")
    return "\n".join(lines)


def _score(classifier: MlClassifier, rows: list[LabeledSample], model_scores: Scores,
           rule_scores: Scores) -> None:
    for item in rows:
        predicted, _ = classifier.classify_instance(item.sample.finding, item.sample.instance)
        model_scores.add(item.verdict, predicted, item.sample.app)
        rule_scores.add(item.verdict, rule_classify(item.sample.finding), item.sample.app)


def _fit(labeled: list[LabeledSample], make_model: Callable | None = None):
    from sklearn.feature_extraction import DictVectorizer
    from sklearn.pipeline import Pipeline

    pipeline = Pipeline([
        ("features", DictVectorizer(sparse=False)),
        ("model", (make_model or _decision_tree)()),
    ])
    pipeline.fit([features.extract(item.sample) for item in labeled], [int(item.verdict) for item in labeled])
    return pipeline


def _decision_tree():
    from sklearn.tree import DecisionTreeClassifier

    # Depth 4 keeps the tree readable and, on ~200 rows, deeper trees overfit (compare()).
    return DecisionTreeClassifier(max_depth=4, min_samples_leaf=3, random_state=0)


def _logistic_regression():
    from sklearn.linear_model import LogisticRegression

    return LogisticRegression(max_iter=3000, class_weight="balanced", C=0.5)


def _deep_tree():
    from sklearn.tree import DecisionTreeClassifier

    return DecisionTreeClassifier(max_depth=8, min_samples_leaf=3, random_state=0)


def _random_forest():
    from sklearn.ensemble import RandomForestClassifier

    return RandomForestClassifier(n_estimators=300, min_samples_leaf=2, random_state=0)


CANDIDATES: dict[str, Callable] = {
    "decision tree, depth 4": _decision_tree,
    "decision tree, depth 8": _deep_tree,
    "logistic regression": _logistic_regression,
    "random forest": _random_forest,
}


def _condition(name: str, threshold: float, went_right: bool) -> str:
    # One-hot columns ("category=headers") and 0/1 flags are split at 0.5.
    if "=" in name and threshold == 0.5:
        return name if went_right else f"not {name}"
    if name.startswith(("is_", "has_", "evidence_")) and threshold == 0.5:
        return f"{name}: {'yes' if went_right else 'no'}"
    return f"{name} {'>' if went_right else '<='} {threshold:.1f}"


def _prf(scores: tuple[float, float, float]) -> str:
    return "/".join(f"{value:.2f}" for value in scores)


@dataclass
class Scores:
    """Confusion counts, overall and per app."""

    pairs: list[tuple[Verdict, Verdict, str]] = field(default_factory=list)

    def add(self, truth: Verdict, predicted: Verdict, app: str) -> None:
        self.pairs.append((truth, predicted, app))

    def accuracy(self, app: str | None = None) -> float:
        rows = self._rows(app)
        return sum(t == p for t, p, _ in rows) / len(rows) if rows else 0.0

    def precision_recall_f1(self, verdict: Verdict, app: str | None = None) -> tuple[float, float, float]:
        rows = self._rows(app)
        tp = sum(t == verdict and p == verdict for t, p, _ in rows)
        fp = sum(t != verdict and p == verdict for t, p, _ in rows)
        fn = sum(t == verdict and p != verdict for t, p, _ in rows)
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        return precision, recall, f1

    def macro_f1(self, app: str | None = None) -> float:
        present = {t for t, _, _ in self._rows(app)}
        return sum(self.precision_recall_f1(v, app)[2] for v in present) / len(present) if present else 0.0

    def confusion(self) -> Counter:
        return Counter((t, p) for t, p, _ in self.pairs)

    def _rows(self, app: str | None):
        return [row for row in self.pairs if app is None or row[2] == app]


@dataclass(frozen=True)
class Evaluation:
    apps: list[str]
    model: Scores
    rules: Scores
    test_apps: list[str] = field(default_factory=list)
    test_model: Scores = field(default_factory=Scores)
    test_rules: Scores = field(default_factory=Scores)

    def report(self) -> str:
        header = (f"1. Leave-one-app-out over {len(self.apps)} development apps "
                  f"({', '.join(self.apps)}), {len(self.model.pairs)} labeled instances")
        lines = [header, ""]
        lines += _table(self.model, self.rules)
        lines += ["", "Per held-out app (accuracy, model vs rules):"]
        lines += [f"  {app:<14}{self.model.accuracy(app):>6.0%}{self.rules.accuracy(app):>8.0%}" for app in self.apps]
        lines += ["", "Model confusion (truth -> predicted):"]
        lines += [f"  {t.label:<15}-> {p.label:<15}{n:>4}" for (t, p), n in sorted(self.model.confusion().items())]
        lines += ["", "2. Final test (trained on the development apps, never used to choose the model)"]
        if not self.test_model.pairs:
            lines.append("  no labeled rows from the test apps yet: " + ", ".join(sorted(TEST_APPS)))
            return "\n".join(lines)
        lines += [f"  {', '.join(self.test_apps)}: {len(self.test_model.pairs)} labeled instances", ""]
        lines += _table(self.test_model, self.test_rules)
        lines += ["", "Model confusion on the test apps (truth -> predicted):"]
        lines += [f"  {t.label:<15}-> {p.label:<15}{n:>4}"
                  for (t, p), n in sorted(self.test_model.confusion().items())]
        return "\n".join(lines)


def _table(model: Scores, rules: Scores) -> list[str]:
    lines = [f"{'':<22}{'model':>16}{'rules':>16}",
             f"{'accuracy':<22}{model.accuracy():>16.0%}{rules.accuracy():>16.0%}",
             f"{'macro F1':<22}{model.macro_f1():>16.2f}{rules.macro_f1():>16.2f}"]
    for verdict in Verdict:
        model_prf, rules_prf = _prf(model.precision_recall_f1(verdict)), _prf(rules.precision_recall_f1(verdict))
        lines.append(f"{verdict.label + ' P/R/F1':<22}{model_prf:>16}{rules_prf:>16}")
    return lines
