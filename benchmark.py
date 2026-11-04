"""Run the agreed feasibility gate without selecting successful seeds."""
import importlib.metadata
import json
import platform
import time
from pathlib import Path
from shor import AttackFailure, run_factorization


def main():
    versions = {name: importlib.metadata.version(name) for name in
                ("qiskit", "qiskit-aer", "numpy", "cryptography")}
    import qiskit_aer  # Confirm installation is complete before starting trials.
    rows = []
    for seed in range(20):
        started = time.perf_counter()
        try:
            answer = run_factorization(seed=seed)
            row = {"seed": seed, "success": True, **answer}
        except AttackFailure as error:
            row = {"seed": seed, "success": False, "error": str(error)}
        row["wall_seconds"] = time.perf_counter()-started
        rows.append(row)
        print(f"seed={seed}: success={row['success']} seconds={row['wall_seconds']:.3f}", flush=True)
    passed = sum(row["success"] for row in rows) >= 19 and all(row["wall_seconds"] < 30 for row in rows)
    report = {"platform": platform.platform(), "processor": platform.processor(),
              "python": platform.python_version(),
              "versions": versions,
              "configuration": {"counting_qubits": 12, "work_qubits": 6,
                                "shots_per_batch": 1024, "max_batches": 3,
                                "timeout_seconds": 30, "threads": 1,
                                "simulator": "CPU statevector", "fusion": False},
              "success_count": sum(row["success"] for row in rows),
              "passed": passed, "runs": rows}
    Path(__file__).with_name("benchmark_report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"Gate passed: {passed}")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
