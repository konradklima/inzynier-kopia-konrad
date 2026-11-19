"""Training and evaluation on labels made up from the saved reports. Skipped without scikit-learn."""

from pathlib import Path
import pytest
from alert_scanner.cli import main as scanner_main
from alert_scanner.domain import Verdict
from alert_scanner.ml import dataset
from alert_scanner.ml.cli import main as ml_main
from alert_scanner.ml.features import STATIC_EXTENSIONS
from alert_scanner.risk_rules import classify
from test_ml_dataset import fill_labels

pytest.importorskip("sklearn")
REPORTS = Path(__file__).parent.parent / "reports"


@pytest.fixture
def labels_dir(tmp_path):
    """Labels from the rules, except that anything on a static file is noise.

    That is a pattern the rules cannot express, so a working model must beat them.
    """
    samples = dataset.load_samples(REPORTS)
    dataset.write_label_sheet(samples, tmp_path / "todo.csv")
    by_fingerprint = {sample.fingerprint: sample for sample in samples}

    def label_for(row):
        sample = by_fingerprint[row["fingerprint"]]
        extension = sample.path.rsplit(".", 1)[-1] if "." in sample.path.rsplit("/", 1)[-1] else ""
        verdict = Verdict.NOISE if extension in STATIC_EXTENSIONS else classify(sample.finding)
        return verdict.label.replace(" ", "_")

    fill_labels(tmp_path / "todo.csv", tmp_path / "team.csv", label_for)
    return tmp_path


def test_model_beats_the_rules_on_a_pattern_the_rules_cannot_see(labels_dir, capsys):
    from alert_scanner.ml import model

    labeled = dataset.labeled_samples(dataset.load_samples(REPORTS), dataset.read_labels(labels_dir))
    evaluation = model.evaluate(labeled)

    assert len(evaluation.apps) >= 2
    assert evaluation.model.accuracy() > evaluation.rules.accuracy()
    assert "Leave-one-app-out" in evaluation.report()


def test_final_test_app_stays_out_of_model_choice(labels_dir):
    from alert_scanner.ml import model

    labeled = dataset.labeled_samples(dataset.load_samples(REPORTS), dataset.read_labels(labels_dir))
    evaluation = model.evaluate(labeled, test_apps=frozenset({"webgoat"}))

    assert "webgoat" not in evaluation.apps
    assert evaluation.test_apps == ["webgoat"]
    assert {app for _, _, app in evaluation.test_model.pairs} == {"webgoat"}
    assert "2. Final test" in evaluation.report()


def test_the_tree_explains_its_verdict(labels_dir):
    from alert_scanner.ml import model

    labeled = dataset.labeled_samples(dataset.load_samples(REPORTS), dataset.read_labels(labels_dir))
    classifier = model.train(labeled)
    static_file = next(i.sample for i in labeled if i.sample.path.endswith(".css"))

    assert classifier.explain(static_file)
    assert "class: noise" in classifier.rules_text()


def test_an_alert_type_the_model_never_saw_is_left_to_the_rules(labels_dir):
    from alert_scanner.domain import Confidence, Finding, Location, Severity
    from alert_scanner.ml import model

    labeled = dataset.labeled_samples(dataset.load_samples(REPORTS), dataset.read_labels(labels_dir))
    classifier = model.train(labeled)
    unseen = Finding("99999", "Backup File Disclosure", Severity.MEDIUM, Confidence.MEDIUM,
                     Location("http://t/passwords/wp-config.bak"))

    verdict, reason = classifier.classify_with_reason(unseen)

    assert "99999" not in classifier.known_rules
    assert verdict == classify(unseen)
    assert reason.startswith("rules:")


def test_diff_lists_where_model_and_rules_disagree(labels_dir, tmp_path, capsys):
    model_path = tmp_path / "classifier.joblib"
    common = ["--reports", str(REPORTS), "--labels", str(labels_dir)]
    ml_main([*common, "train", "--out", str(model_path)])

    exit_code = ml_main([*common, "diff", "--report", str(REPORTS / "zap-full-juiceshop.json"),
                         "--target", "http://host.docker.internal:3000", "--model", str(model_path)])

    assert exit_code == 0
    assert "they disagree on" in capsys.readouterr().out


def test_train_then_classify_a_report_with_the_model(labels_dir, tmp_path, capsys):
    model_path = tmp_path / "classifier.joblib"
    common = ["--reports", str(REPORTS), "--labels", str(labels_dir)]
    assert ml_main([*common, "train", "--out", str(model_path)]) == 0

    exit_code = scanner_main([
        "--report", str(REPORTS / "zap-full-juiceshop.json"),
        "--target", "http://host.docker.internal:3000",
        "--classifier", "ml", "--model", str(model_path), "--no-store",
    ])

    output = capsys.readouterr().out
    assert exit_code == 0
    assert "Classifier: trained model" in output
    assert "Issues to fix:" in output
