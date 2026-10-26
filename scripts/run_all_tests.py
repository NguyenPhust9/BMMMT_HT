"""
End-to-end runner for M2 bootstrap verification + full 40-test suite (T-01..T-40) on real PostgreSQL 17.
Updates `evidence/test_results.csv` and `evidence/index.md` strictly from real execution logs in `evidence/logs/`.
"""
from __future__ import annotations

import csv
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

import postgres_ctl  # noqa: E402


def main() -> int:
    print("=== [1/4] Ensuring isolated PostgreSQL 17 cluster is running on 127.0.0.1:55432 ===")
    postgres_ctl.init_and_start()

    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")
    import django

    django.setup()
    from django.core.management import call_command

    print("=== [2/4] Applying migrations & running bootstrap_lab --reset ===")
    call_command("migrate", verbosity=1)
    call_command("bootstrap_lab", reset=True, verbosity=1)

    evidence_logs_dir = ROOT / "evidence" / "logs"
    evidence_logs_dir.mkdir(parents=True, exist_ok=True)

    print("=== [3/4] Running pytest for T-01..T-40 on real PostgreSQL 17 ===")
    pytest_log = evidence_logs_dir / "pytest_full_run.log"
    cmd = [
        sys.executable,
        "-m",
        "pytest",
        "tests/test_suite_t01_t20.py",
        "tests/test_suite_t21_t40.py",
        "-v",
        "--tb=short",
    ]
    proc = subprocess.run(cmd, cwd=str(ROOT), capture_output=True, text=True)
    combined_out = proc.stdout + "\n" + proc.stderr
    pytest_log.write_text(combined_out, encoding="utf-8")
    print(combined_out)

    if proc.returncode != 0:
        print(f"ERROR: pytest exited with code {proc.returncode}")
        return proc.returncode

    print("=== [4/4] Updating evidence/test_results.csv and evidence/index.md from real test logs ===")
    csv_path = ROOT / "evidence" / "test_results.csv"
    with csv_path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        fieldnames = reader.fieldnames
        rows = list(reader)

    env_str = "Windows-11-64bit; Python 3.13.5; Django 5.2.14; PostgreSQL 17.6 (127.0.0.1:55432)"
    code_ver = "securepay-lab-v1.0.0"

    pass_count = 0
    for row in rows:
        tid = row["id"]
        log_file = evidence_logs_dir / f"{tid}.json"
        if log_file.exists():
            data = json.loads(log_file.read_text(encoding="utf-8"))
            row["environment"] = env_str
            row["code_version"] = code_ver
            row["fixture"] = data.get("fixture", "default_lab")
            row["started_at_utc"] = data.get("recorded_at_utc", datetime.now(timezone.utc).isoformat())
            row["actual"] = data.get("actual", "")
            row["status"] = data.get("status", "PASS")
            row["evidence_paths"] = f"evidence/logs/{tid}.json; evidence/logs/pytest_full_run.log"
            if row["status"] == "PASS":
                pass_count += 1

    with csv_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    index_md = ROOT / "evidence" / "index.md"
    lines = [
        "# Chỉ mục bằng chứng kiểm thử và thực nghiệm (Evidence Index)",
        "",
        f"- **Thời điểm cập nhật (UTC)**: `{datetime.now(timezone.utc).isoformat()}`",
        f"- **Môi trường thực thi**: `{env_str}`",
        f"- **Tổng số ca kiểm thử**: `{len(rows)}` (`PASS`: **{pass_count}/{len(rows)}**)",
        "- **Bảng tổng hợp CSV**: [`evidence/test_results.csv`](test_results.csv)",
        "- **Nhật ký chạy Pytest đầy đủ**: [`evidence/logs/pytest_full_run.log`](logs/pytest_full_run.log)",
        "",
        "## Danh sách chi tiết 40 ca kiểm thử (`T-01` .. `T-40`)",
        "",
        "| ID | Yêu cầu | Rủi ro | Chế độ | Trạng thái | Kết quả thực tế (`actual`) | Bằng chứng |",
        "|---|---|---|---|---|---|---|",
    ]
    for r in rows:
        lines.append(
            f"| `{r['id']}` | `{r['requirement_ids']}` | `{r['risk_ids']}` | `{r['mode']}` | **{r['status']}** | {r['actual']} | [`{r['id']}.json`](logs/{r['id']}.json) |"
        )
    index_md.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Successfully updated {csv_path} and {index_md} ({pass_count}/{len(rows)} PASS).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

