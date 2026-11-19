"""Dataset, fingerprints and features for the ML classifier. No scikit-learn needed."""

import csv
from pathlib import Path
from alert_scanner.domain import Confidence, Finding, Instance, Location, Severity, Verdict
from alert_scanner.ml import dataset, features
from alert_scanner.ml.cli import main

REPORTS = Path(__file__).parent.parent / "reports"


def test_normalized_path_drops_host_ids_and_query_values():
    assert dataset.normalized_path("http://t:3000/rest/products/42/reviews?limit=5&page=2") == \
        "/rest/products/{id}/reviews?limit&page"
    assert dataset.normalized_path("http://t:3000/#/search?q=x") == "/#/search"


def test_fingerprint_survives_a_rescan_but_separates_apps():
    first = _sample(uri="http://host.docker.internal:3000/rest/user/7?x=1")
    rescan = _sample(uri="http://localhost:3000/rest/user/9?x=2")
    other_app = _sample(app="dvwa", uri="http://localhost:4280/rest/user/7?x=1")

    assert first.fingerprint == rescan.fingerprint
    assert first.fingerprint != other_app.fingerprint


def test_label_sheet_round_trip_and_majority_vote(tmp_path):
    sample = _sample()
    dataset.write_label_sheet([sample], tmp_path / "todo.csv")
    for person, label in (("a", "real"), ("b", "noise"), ("c", "real")):
        fill_labels(tmp_path / "todo.csv", tmp_path / f"{person}.csv", lambda row, label=label: label)

    [labeled] = dataset.labeled_samples([sample], dataset.read_labels(tmp_path))
    assert "http://t:3000/rest/user/login" in (tmp_path / "todo.csv").read_text(encoding="utf-8")

    assert labeled.verdict == Verdict.REAL
    assert labeled.votes == {Verdict.REAL: 2, Verdict.NOISE: 1}
    assert not labeled.agreed


def test_label_spelling_variants_mean_the_same_label(tmp_path):
    sample = _sample()
    dataset.write_label_sheet([sample], tmp_path / "todo.csv")
    for person, label in (("a", "false-positive"), ("b", " False Positive "), ("c", "false_positive")):
        fill_labels(tmp_path / "todo.csv", tmp_path / f"{person}.csv", lambda row, label=label: label)

    votes = dataset.read_labels(tmp_path)[sample.fingerprint]

    assert set(votes.values()) == {Verdict.FALSE_POSITIVE}


def test_a_team_label_overrides_the_pre_label():
    sample = _sample()
    pre_labeled_only = {sample.fingerprint: {"prelabels": Verdict.NOISE}}
    checked = {sample.fingerprint: {"prelabels": Verdict.NOISE, "dawid": Verdict.REAL}}

    [before] = dataset.labeled_samples([sample], pre_labeled_only)
    [after] = dataset.labeled_samples([sample], checked)

    assert (before.verdict, before.human_checked) == (Verdict.NOISE, False)
    assert (after.verdict, after.human_checked, after.votes) == (Verdict.REAL, True, {Verdict.REAL: 1})


def test_a_page_seen_in_several_scans_is_one_labeled_sample():
    passive = _sample(mode="baseline")
    active = _sample(mode="full", attack="'(")
    labels = {passive.fingerprint: {"a": Verdict.REAL}}

    [labeled] = dataset.labeled_samples([passive, active], labels)

    assert labeled.sample is active


def test_features_see_the_content_not_only_severity():
    api_hit = features.extract(_sample(uri="http://t/rest/products/search?q=1", param="q",
                                       attack="'(", evidence="SQLITE_ERROR: near \"(\""))
    static_asset = features.extract(_sample(uri="http://t/main.js", param="", evidence="1700000000"))

    assert (api_hit["is_api_path"], api_hit["evidence_sql_error"], api_hit["param_kind"]) == (1.0, 1.0, "search")
    assert (static_asset["is_static_asset"], static_asset["evidence_is_number"]) == (1.0, 1.0)
    assert set(api_hit) == set(features.feature_names())


def test_is_file_separates_files_from_pages_and_app_routes():
    is_file = {uri: features.extract(_sample(uri=uri))["is_file"] for uri in (
        "http://t/ftp/package.json.bak", "http://t/ftp/encrypt.pyc", "http://t/main.js",
        "http://t/login.php", "http://t/WebGoat/register.mvc", "http://t/rest/user/login",
        "http://t/juice-shop/build/routes/fileServer.js:52:13",
    )}

    assert [uri.rsplit("/", 1)[-1] for uri, flag in is_file.items() if flag] == \
        ["package.json.bak", "encrypt.pyc", "main.js"]


def test_samples_come_from_every_instance_of_the_saved_reports():
    samples = dataset.samples_from_report(REPORTS / "zap-full-juiceshop.json")

    assert len(samples) == 64
    assert {sample.app for sample in samples} == {"juiceshop"}
    assert {sample.mode for sample in samples} == {"full"}


def test_calibration_subset_covers_every_app():
    samples = dataset.load_samples(REPORTS)

    subset = dataset.calibration_samples(samples, 40)

    assert len(subset) == 40
    assert len({sample.fingerprint for sample in subset}) == 40
    assert {sample.app for sample in subset} == {sample.app for sample in samples}


def test_templates_are_not_votes_and_todo_lists_only_unlabeled_rows(tmp_path, capsys):
    common = ["--reports", str(REPORTS), "--labels", str(tmp_path)]
    main([*common, "sheet", "--all"])
    with open(tmp_path / "todo.csv", newline="", encoding="utf-8") as sheet:
        all_rows = list(csv.DictReader(sheet))
    first = all_rows[0]["fingerprint"]
    def label_first(row):
        return "real" if row["fingerprint"] == first else ""

    fill_labels(tmp_path / "todo.csv", tmp_path / "rudolf.csv", label_first)
    fill_labels(tmp_path / "todo.csv", tmp_path / "todo.csv", label_first)

    assert dataset.read_labels(tmp_path) == {first: {"rudolf": Verdict.REAL}}
    main([*common, "sheet"])
    with open(tmp_path / "todo.csv", newline="", encoding="utf-8") as sheet:
        assert len(list(csv.DictReader(sheet))) == len(all_rows) - 1


def test_ml_cli_writes_a_sheet_and_stats(tmp_path, capsys):
    assert main(["--reports", str(REPORTS), "--labels", str(tmp_path), "sheet"]) == 0
    assert main(["--reports", str(REPORTS), "--labels", str(tmp_path), "stats"]) == 0
    output = capsys.readouterr().out
    assert "wierszy" in output and "nieoznaczone" in output


def fill_labels(template, out, label_for):
    """Copy a label sheet and fill the `label` column, like a team member would."""
    with open(template, newline="", encoding="utf-8") as sheet:
        rows = list(csv.DictReader(sheet))
    for row in rows:
        row["label"] = label_for(row)
    with open(out, "w", newline="", encoding="utf-8") as sheet:
        writer = csv.DictWriter(sheet, fieldnames=dataset.LABEL_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)


def _sample(*, app="juiceshop", uri="http://t:3000/rest/user/login", param="email",
            attack="", evidence="", mode="full"):
    location = Location(uri, "POST", param)
    instance = Instance(location, attack, evidence)
    finding = Finding("40018", "SQL Injection", Severity.HIGH, Confidence.MEDIUM, location,
                      cwe_id=89, instances=(instance,))
    return dataset.Sample(app, mode, finding, instance)
