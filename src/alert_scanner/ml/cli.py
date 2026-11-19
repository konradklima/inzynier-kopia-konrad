"""Command line for the ML side: label sheets, dataset statistics, training, evaluation.

    alert-scanner-ml sheet        write data/labels/todo.csv: rows nobody has labeled yet
    alert-scanner-ml sheet --calibration 40 --out calibration.csv
                                  a spread-out subset that everyone labels, for `agreement`
    alert-scanner-ml stats        how many samples and labels we have, per app and verdict
    alert-scanner-ml agreement    how often the team members gave the same label
    alert-scanner-ml compare      leave-one-app-out for every candidate model (dev apps only)
    alert-scanner-ml evaluate     leave-one-app-out on the dev apps, then the final test app
    alert-scanner-ml train        fit on the dev apps, save models/classifier.joblib, print the tree
    alert-scanner-ml diff --report FILE   where the model and the rules disagree on one report
The ML commands need scikit-learn.
"""

from __future__ import annotations
import argparse
import sys
from collections import Counter, defaultdict
from itertools import combinations
from pathlib import Path
from alert_scanner.domain import Verdict
from alert_scanner.ml import dataset

REPORTS_DIR = Path("reports")
LABELS_DIR = Path("data/labels")


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    return args.handler(args)


def _sheet(args: argparse.Namespace) -> int:
    samples = dataset.load_samples(args.reports)
    if args.calibration:
        samples = dataset.calibration_samples(samples, args.calibration)
    elif not args.all:
        labeled = dataset.read_labels(args.labels)
        samples = [sample for sample in samples if sample.fingerprint not in labeled]
    args.labels.mkdir(parents=True, exist_ok=True)
    written = dataset.write_label_sheet(samples, args.labels / args.out)
    print(f"{written} rows to label ({len({s.app for s in samples})} apps) -> {args.labels / args.out}")
    return 0


def _stats(args: argparse.Namespace) -> int:
    samples = dataset.load_samples(args.reports)
    labels = dataset.read_labels(args.labels)
    labeled = dataset.labeled_samples(samples, labels)
    unique = {sample.fingerprint for sample in samples}
    checked = sum(item.human_checked for item in labeled)
    print(f"instances: {len(samples)}, unique fingerprints: {len(unique)}, labeled: {len(labeled)} "
          f"(checked by the team: {checked}, pre-labels only: {len(labeled) - checked})")
    per_app: dict[str, Counter] = defaultdict(Counter)
    for item in labeled:
        per_app[item.sample.app][item.verdict] += 1
    for app, counts in sorted(per_app.items()):
        breakdown = ", ".join(f"{counts[v]} {v.label}" for v in Verdict)
        print(f"  {app:<12} {sum(counts.values()):>4} labeled: {breakdown}")
    unlabeled = Counter(sample.app for sample in samples if sample.fingerprint not in labels)
    if unlabeled:
        print("  unlabeled: " + ", ".join(f"{app} {n}" for app, n in sorted(unlabeled.items())))
    return 0


def _agreement(args: argparse.Namespace) -> int:
    labels = dataset.read_labels(args.labels)
    people = sorted({person for votes in labels.values() for person in votes})
    if len(people) < 2:
        print("Need labels from at least two people for an agreement score.")
        return 1
    for first, second in combinations(people, 2):
        shared = [votes for votes in labels.values() if first in votes and second in votes]
        if not shared:
            print(f"{first} vs {second}: no shared rows")
            continue
        same = sum(votes[first] == votes[second] for votes in shared)
        print(f"{first} vs {second}: {same}/{len(shared)} agree ({100 * same / len(shared):.0f}%)")
    return 0


def _evaluate(args: argparse.Namespace) -> int:
    from alert_scanner.ml import model

    labeled = _labeled(args)
    print(model.evaluate(labeled).report())
    return 0


def _compare(args: argparse.Namespace) -> int:
    from alert_scanner.ml import model

    print(model.compare(_labeled(args)))
    return 0


def _train(args: argparse.Namespace) -> int:
    from alert_scanner.ml import model

    labeled = _labeled(args)
    used = [item for item in labeled if item.sample.app not in model.TEST_APPS]
    classifier = model.train(labeled)
    saved = classifier.save(args.out)
    apps = ", ".join(sorted({item.sample.app for item in used}))
    print(f"Trained on {len(used)} labeled instances from {apps} -> {saved}")
    print(f"(left out as the test set: {', '.join(sorted(model.TEST_APPS))})")
    print()
    print(classifier.rules_text())
    return 0


def _diff(args: argparse.Namespace) -> int:
    from alert_scanner.ml.model import MlClassifier
    from alert_scanner.risk_rules import classify
    from alert_scanner.zap_parser import guess_target, load_report, parse_report

    report = load_report(args.report)
    target = args.target or guess_target(report)
    classifier = MlClassifier.load(args.model)
    findings = parse_report(report, target)
    rows = [(finding, classify(finding), *classifier.classify_with_reason(finding)) for finding in findings]
    changed = [row for row in rows if row[1] != row[2]]
    real_by_rules = sum(rule == Verdict.REAL for _, rule, _, _ in rows)
    real_by_model = sum(model == Verdict.REAL for _, _, model, _ in rows)
    print(f"{target}: {len(findings)} alert types")
    print(f"  issues to fix: rules {real_by_rules}, model {real_by_model}; they disagree on {len(changed)}")
    for finding, rule, model, reason in changed:
        print()
        print(f"  {finding.name}  {finding.location.short_path()}")
        print(f"    rules: {rule.label:<15} model: {model.label}")
        print(f"    why:   {reason}")
    return 0


def _labeled(args: argparse.Namespace):
    labeled = dataset.labeled_samples(dataset.load_samples(args.reports), dataset.read_labels(args.labels))
    if not labeled:
        print("No labeled samples. Fill in data/labels/<person>.csv first.", file=sys.stderr)
        raise SystemExit(1)
    return labeled


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="alert-scanner-ml", description=__doc__.split("\n\n")[0])
    parser.add_argument("--reports", type=Path, default=REPORTS_DIR, help="folder with zap-<mode>-<app>.json")
    parser.add_argument("--labels", type=Path, default=LABELS_DIR, help="folder with <person>.csv")
    commands = parser.add_subparsers(dest="command", required=True)

    sheet = commands.add_parser("sheet", help="write the CSV to label by hand")
    sheet.add_argument("--out", default="todo.csv", help="file name inside the labels folder")
    sheet.add_argument("--calibration", type=int, metavar="N",
                       help="only N spread-out rows, for the agreement round")
    sheet.add_argument("--all", action="store_true", help="include rows that are already labeled")
    sheet.set_defaults(handler=_sheet)
    commands.add_parser("stats", help="sample and label counts").set_defaults(handler=_stats)
    commands.add_parser("agreement", help="inter-annotator agreement").set_defaults(handler=_agreement)
    commands.add_parser("compare", help="compare candidate models").set_defaults(handler=_compare)
    commands.add_parser("evaluate", help="leave-one-app-out, then the final test").set_defaults(handler=_evaluate)
    train = commands.add_parser("train", help="fit on all labels and save the model")
    train.add_argument("--out", type=Path, default=Path("models/classifier.joblib"))
    train.set_defaults(handler=_train)
    diff = commands.add_parser("diff", help="model vs rules on one ZAP report")
    diff.add_argument("--report", required=True, type=Path, help="ZAP JSON report")
    diff.add_argument("--target", help="scanned site (default: the site with the most alerts)")
    diff.add_argument("--model", type=Path, default=Path("models/classifier.joblib"))
    diff.set_defaults(handler=_diff)
    return parser


if __name__ == "__main__":
    raise SystemExit(main())
