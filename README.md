# Suspicious Login Log Analyser

An educational Python example that counts log lines containing `FAILED_LOGIN` for each IP address and reports addresses with at least five matching entries.

## Current status

The original Python source is preserved below. This repository currently has no standalone Python script or sample input log. The existing `reports/report.txt` is a placeholder, not evidence of a successful run.

## What the example demonstrates

- Reading a text file line by line.
- Counting matching events with `collections.Counter`.
- Applying a threshold.
- Writing a plain-text report.

A flagged address is a review signal, not proof of an attack. The example does not validate IP addresses, apply a time window, monitor live systems or block traffic.

## Try the example locally

1. Save the Python code below as `analyser.py`.
2. Create `sample_logs` and `reports` folders beside it.
3. Create `sample_logs/access.log` using the format `IP - TIMESTAMP - EVENT`.
4. From that folder, run:

```bash
python analyser.py
```

Python's standard library is sufficient. The example assumes that the input file and output folder already exist.

### Illustrative input

Use these synthetic entries for a small manual check:

```text
192.0.2.10 - 2026-11-01T09:00:00 - FAILED_LOGIN
192.0.2.10 - 2026-11-01T09:01:00 - FAILED_LOGIN
192.0.2.10 - 2026-11-01T09:02:00 - FAILED_LOGIN
192.0.2.10 - 2026-11-01T09:03:00 - FAILED_LOGIN
192.0.2.10 - 2026-11-01T09:04:00 - FAILED_LOGIN
192.0.2.20 - 2026-11-01T09:05:00 - SUCCESS_LOGIN
```

Expected report for this illustrative input, not a recorded test result:

```text
Suspicious IP Report
====================

192.0.2.10 triggered 5 failed logins.
```

## Python source

```python
import collections

FAILED_KEYWORD = "FAILED_LOGIN"
THRESHOLD = 5  # failed logins before flagging


def parse_log(path):
    """Reads log file line by line."""
    with open(path, "r") as f:
        for line in f:
            yield line.strip()


def find_suspicious_ips(log_lines):
    """Counts failed login attempts per IP."""
    failed_counts = collections.Counter()

    for line in log_lines:
        if FAILED_KEYWORD in line:
            # assume log format: "IP - TIMESTAMP - EVENT"
            parts = line.split(" - ")
            ip = parts[0]
            failed_counts[ip] += 1

    # Only return IPs that meet or exceed the threshold
    return {ip: count for ip, count in failed_counts.items() if count >= THRESHOLD}


def write_report(suspicious_ips, report_path):
    """Writes the output report."""
    with open(report_path, "w") as f:
        f.write("Suspicious IP Report\n")
        f.write("====================\n\n")

        if not suspicious_ips:
            f.write("No suspicious IPs found.\n")
            return

        for ip, count in suspicious_ips.items():
            f.write(f"{ip} triggered {count} failed logins.\n")


if __name__ == "__main__":
    log_path = "sample_logs/access.log"
    report_path = "reports/report.txt"

    lines = list(parse_log(log_path))
    suspicious_ips = find_suspicious_ips(lines)
    write_report(suspicious_ips, report_path)

    print(f"Report generated: {report_path}")
```

## Limitations and next steps

This learning example uses substring matching for `FAILED_LOGIN` and assumes consistent delimiters. Malformed lines are not rejected, and failed logins are counted across the whole file regardless of timestamp. Add a standalone script, sample logs and actual test evidence before presenting it as a complete runnable repository.
