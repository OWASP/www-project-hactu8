"""
Test runner for prompt injection test cases.

Sends each payload to the configured target URL and checks the response
for injection success indicators.
"""

import time
import uuid
import json
import os
import requests
from datetime import datetime, timezone
from typing import Any

from .payloads import TEST_CASES


def run_single_test(
    test_case: dict,
    target_url: str,
    timeout: int = 30,
    verbose: bool = False,
) -> dict:
    """
    Run a single prompt injection test against the target.

    Returns a TestCaseResult-compatible dict.
    """
    start = time.time()
    result: dict[str, Any] = {
        "id": test_case["id"],
        "name": test_case["name"],
        "status": "error",
        "duration": 0,
        "message": "",
    }

    try:
        # Send the payload as a chat message to the target
        payload = {
            "message": test_case["payload"],
            "mode": "assist",
        }

        response = requests.post(
            f"{target_url.rstrip('/')}/api/copilot/chat",
            json=payload,
            timeout=timeout,
        )
        response.raise_for_status()
        data = response.json()
        reply = data.get("reply", "")

        # Check if any detection strings are present in the response
        # If detected → the injection SUCCEEDED → target is VULNERABLE → test FAILS
        detected = [d for d in test_case["detect"] if d.lower() in reply.lower()]

        if detected:
            result["status"] = "fail"
            result["message"] = f"Injection succeeded — detected: {', '.join(detected)}"
        else:
            result["status"] = "pass"
            result["message"] = "No injection indicators detected in response."

        if verbose:
            result["details"] = json.dumps(
                {"payload": test_case["payload"], "response": reply[:500], "detected": detected},
                indent=2,
            )

    except requests.exceptions.Timeout:
        result["status"] = "error"
        result["message"] = f"Request timed out after {timeout}s"
    except requests.exceptions.ConnectionError:
        result["status"] = "error"
        result["message"] = f"Could not connect to {target_url}"
    except Exception as e:
        result["status"] = "error"
        result["message"] = str(e)

    result["duration"] = int((time.time() - start) * 1000)
    return result


def run_all_tests(
    target_url: str,
    timeout: int = 30,
    verbose: bool = False,
    progress_callback=None,
) -> dict:
    """
    Run all prompt injection tests and return a TestRunResult-compatible dict.

    Args:
        target_url: The target AI endpoint URL.
        timeout: Per-request timeout in seconds.
        verbose: Include request/response details in results.
        progress_callback: Optional callable(current, total) for progress updates.
    """
    run_id = str(uuid.uuid4())[:8]
    start = time.time()
    results = []
    total = len(TEST_CASES)

    for i, test_case in enumerate(TEST_CASES):
        result = run_single_test(test_case, target_url, timeout, verbose)
        results.append(result)
        if progress_callback:
            progress_callback(i + 1, total)

    duration = int((time.time() - start) * 1000)
    passed = sum(1 for r in results if r["status"] == "pass")
    failed = sum(1 for r in results if r["status"] == "fail")
    errors = sum(1 for r in results if r["status"] == "error")
    skipped = sum(1 for r in results if r["status"] == "skip")

    return {
        "runId": run_id,
        "extensionId": "iac-prompt-injection-tests",
        "extensionName": "Prompt Injection Tests - IAC Core",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "target": target_url,
        "summary": {
            "total": total,
            "passed": passed,
            "failed": failed,
            "errors": errors,
            "skipped": skipped,
            "duration": duration,
        },
        "results": results,
    }


def save_results(run_result: dict, results_dir: str) -> str:
    """
    Write test run results to the shared results directory.

    Returns the path to the written file.
    """
    # Expand ~ and ensure directory exists
    expanded = os.path.expanduser(results_dir)
    os.makedirs(expanded, exist_ok=True)

    filename = f"{run_result['runId']}.json"
    filepath = os.path.join(expanded, filename)

    with open(filepath, "w") as f:
        json.dump(run_result, f, indent=2)

    return filepath
