import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import textwrap
from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, List, Tuple


def find_semgrep() -> str:
    """Return the semgrep executable name if available, else empty string."""
    cmd = "semgrep.exe" if os.name == "nt" else "semgrep"
    from shutil import which

    path = which(cmd)
    if path:
        return path
    # try without .exe on Windows
    if os.name == "nt":
        path = which("semgrep")
        if path:
            return path
    return ""


def run(cmd: List[str], cwd: Path = None) -> Tuple[int, str, str]:
    proc = subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    return proc.returncode, proc.stdout, proc.stderr


def ensure_dir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)


def top_level_plugin_dir(path: Path, plugins_root: Path) -> str:
    try:
        rel = path.resolve().relative_to(plugins_root.resolve())
    except Exception:
        return ""
    parts = rel.parts
    return parts[0] if parts else ""


def ingest_zips(zips_dir: Path, plugins_dir: Path, clear: bool = False) -> None:
    import zipfile

    ensure_dir(zips_dir)
    if clear and plugins_dir.exists():
        shutil.rmtree(plugins_dir)
    ensure_dir(plugins_dir)

    zip_files = list(zips_dir.glob("*.zip"))
    if not zip_files:
        print(f"No zip files found in {zips_dir}")
        return

    for zf in zip_files:
        try:
            with zipfile.ZipFile(zf) as z:
                # Detect single top-level folder
                names = [n for n in z.namelist() if not n.endswith("/")]
                top_levels = {n.split("/", 1)[0] for n in names}
                if len(top_levels) == 1:
                    out_dir = plugins_dir / list(top_levels)[0]
                    ensure_dir(out_dir)
                    z.extractall(plugins_dir)
                else:
                    out_dir = plugins_dir / zf.stem
                    ensure_dir(out_dir)
                    z.extractall(out_dir)
            print(f"Extracted: {zf.name} -> {out_dir}")
        except Exception as e:
            print(f"Failed to extract {zf.name}: {e}")


def build_semgrep_cmd(semgrep_bin: str, plugins_dir: Path, rules_dir: Path, timeout: int = 0, jobs: int = 0) -> List[str]:
    cmd = [semgrep_bin, "--config", str(rules_dir), "--json", "--quiet", "--no-git-ignore"]
    if timeout:
        cmd += ["--timeout", str(timeout)]
    if jobs:
        cmd += ["--jobs", str(jobs)]
    cmd += [str(plugins_dir)]
    return cmd


def filter_finding_by_heuristics(f: Dict) -> bool:
    """Return True if finding should be kept; False to drop likely false positive."""
    rule_id = f.get("check_id") or f.get("rule_id") or ""
    extra = f.get("extra", {})
    lines = extra.get("lines") or ""

    # Drop if echo rule but escaping present
    if rule_id.endswith("wordpress.echo.userinput"):
        if re.search(r"esc_(html|attr|url)|wp_kses", lines):
            return False

    # Drop if $wpdb rule and prepare present
    if rule_id.startswith("wordpress.db.query"):
        if "prepare(" in lines:
            return False

    return True


def scan(plugins_dir: Path, rules_dir: Path, out_dir: Path, timeout: int = 0, jobs: int = 0) -> Path:
    ensure_dir(out_dir)
    semgrep_bin = find_semgrep()
    if not semgrep_bin:
        print(
            textwrap.dedent(
                f"""
                [!] Semgrep not found in PATH.
                    Install options (one of):
                      - pipx install semgrep
                      - pip install --user semgrep
                      - scoop install semgrep  (PowerShell)
                      - choco install semgrep  (if Chocolatey installed)

                    After installation, re-run this command.
                """
            ).strip()
        )
        sys.exit(127)

    cmd = build_semgrep_cmd(semgrep_bin, plugins_dir, rules_dir, timeout=timeout, jobs=jobs)
    print("Running:", " ".join(cmd))
    code, out, err = run(cmd)
    if code not in (0, 1):  # 0/1 are OK (1 indicates findings)
        print("Semgrep error:", err)
        sys.exit(code)

    # Save raw JSON
    out_json = out_dir / "semgrep.json"
    with out_json.open("w", encoding="utf-8") as f:
        f.write(out)

    # Load and lightly post-process
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        print("Failed to parse Semgrep output.")
        sys.exit(2)

    results = data.get("results", [])
    kept: List[Dict] = []
    for r in results:
        if filter_finding_by_heuristics(r):
            kept.append(r)

    filtered_path = out_dir / "semgrep.filtered.json"
    with filtered_path.open("w", encoding="utf-8") as f:
        json.dump({"results": kept}, f, ensure_ascii=False, indent=2)

    # Quick console summary
    rule_counts = Counter([(r.get("check_id"), r.get("extra", {}).get("severity")) for r in kept])
    file_counts = Counter([r.get("path") for r in kept])
    print(f"Findings kept after heuristics: {len(kept)}")
    print("Top rules:")
    for (rid, sev), cnt in rule_counts.most_common(10):
        print(f"  {rid} [{sev}]: {cnt}")
    print("Top files:")
    for path, cnt in file_counts.most_common(10):
        print(f"  {path}: {cnt}")

    return filtered_path


def report(filtered_json: Path, plugins_dir: Path, out_dir: Path) -> None:
    ensure_dir(out_dir)
    try:
        data = json.loads(filtered_json.read_text(encoding="utf-8"))
    except Exception as e:
        print(f"Failed to load {filtered_json}: {e}")
        sys.exit(2)

    results = data.get("results", [])
    # Aggregate by plugin, rule id
    by_plugin_rule: Dict[Tuple[str, str], List[Dict]] = defaultdict(list)
    for r in results:
        p = top_level_plugin_dir(Path(r.get("path", "")), plugins_dir)
        rid = r.get("check_id")
        by_plugin_rule[(p, rid)].append(r)

    # Markdown summary
    md = ["# Scan Summary\n"]
    md.append(f"Total findings: {len(results)}\n")
    md.append("## By Plugin & Rule\n")
    for (plugin, rid), items in sorted(by_plugin_rule.items(), key=lambda x: (-len(x[1]), x[0])):
        md.append(f"- {plugin or '(unknown)'} | {rid}: {len(items)}")
    (out_dir / "report.md").write_text("\n".join(md), encoding="utf-8")

    # CSV summary (path,line,rule,severity,message,plugin)
    import csv

    with (out_dir / "summary.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["plugin", "path", "line", "rule", "severity", "message"]) 
        for r in results:
            extra = r.get("extra", {})
            w.writerow([
                top_level_plugin_dir(Path(r.get("path", "")), plugins_dir),
                r.get("path"),
                extra.get("line"),
                r.get("check_id"),
                extra.get("severity"),
                (extra.get("message") or "").replace("\n", " "),
            ])

    print(f"Wrote: {out_dir / 'report.md'}")
    print(f"Wrote: {out_dir / 'summary.csv'}")


def main(argv: List[str]) -> None:
    parser = argparse.ArgumentParser(
        prog="wp_scanner",
        description="WordPress plugin Semgrep regex scanner",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_ingest = sub.add_parser("ingest", help="Extract plugin zip files into a plugins directory")
    p_ingest.add_argument("--zips-dir", "-z", default="plugins_zips", type=Path)
    p_ingest.add_argument("--plugins-dir", "-p", default="plugins", type=Path)
    p_ingest.add_argument("--clear", action="store_true", help="Clear plugins dir before extracting")

    p_scan = sub.add_parser("scan", help="Run Semgrep over plugins with provided rules")
    p_scan.add_argument("--plugins-dir", "-p", default="plugins", type=Path)
    p_scan.add_argument("--rules-dir", "-r", default="rules", type=Path)
    p_scan.add_argument("--out", "-o", default=Path("results"), type=Path)
    p_scan.add_argument("--timeout", type=int, default=0, help="Semgrep timeout seconds (0=disable)")
    p_scan.add_argument("--jobs", type=int, default=0, help="Parallel jobs for Semgrep (0=auto)")

    p_report = sub.add_parser("report", help="Summarize Semgrep JSON results")
    p_report.add_argument("--input", "-i", default=Path("results/semgrep.filtered.json"), type=Path)
    p_report.add_argument("--plugins-dir", "-p", default="plugins", type=Path)
    p_report.add_argument("--out", "-o", default=Path("results"), type=Path)

    args = parser.parse_args(argv)

    if args.cmd == "ingest":
        ingest_zips(args.zips_dir, args.plugins_dir, clear=args.clear)
    elif args.cmd == "scan":
        scan(args.plugins_dir, args.rules_dir, args.out, timeout=args.timeout, jobs=args.jobs)
    elif args.cmd == "report":
        report(args.input, args.plugins_dir, args.out)
    else:
        parser.print_help()


if __name__ == "__main__":
    main(sys.argv[1:])

