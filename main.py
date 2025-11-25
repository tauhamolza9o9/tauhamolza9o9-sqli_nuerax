#!/usr/bin/env python3
"""
main.py — AttackVictor Unified CLI Scanner
------------------------------------------

This CLI orchestrates:
- Target loading (async)
- Detector selection
- Payload generator setup
- WAF bypass engine
- Scan execution
- Report merging + saving

Detectors supported:
- error_based
- boolean_based
- time_based
- nosql
- union_based
- stacked_queries
- second_order
- oblique (combined strategy)

"""

import argparse
import asyncio
import sys
import time

from utils import (
    make_logger,
    create_session,
    load_payload_generators,
    create_bypass_engines,
    merge_scan_results,
    save_report
)

from config import (
    ENGINE_DEFAULTS,
    SCAN_STRATEGIES,
    DETECTION_MODES
)

# Detectors
from target_loader import TargetLoader
from error_based import AdvancedErrorBasedDetector
from boolean_based import AdvancedBooleanBasedDetector
from time_based import AdvancedTimeBasedDetector
from nosql_injection import AdvancedNoSQLInjectionDetector
from union_based import UnionBasedDetector
from stacked_queries import StackedQueryDetector
from second_order import SecondOrderDetector
from oblique import run_error_based_scan, run_boolean_based_scan, run_time_based_scan, run_nosql_injection_scan


# ---------------------------------------------------------
# ASYNC target loader wrapper
# ---------------------------------------------------------
async def async_load_target(url, timeout=15, verify_ssl=False):
    loader = TargetLoader(timeout=timeout, verify_ssl=verify_ssl)
    result = await loader.load(url)
    await loader.close()
    return result


# ---------------------------------------------------------
# Run technique detectors
# ---------------------------------------------------------
def run_detectors(args, target_info, logger):

    results = {
        "target": {
            "input": args.target,
            "final_url": target_info.get("final_url"),
            "status": target_info.get("status"),
            "alive": target_info.get("alive"),
            "redirect_chain": target_info.get("redirect_chain", [])
        }
    }

    # Shared objects
    session = create_session()
    payloads = load_payload_generators()
    bypass = create_bypass_engines(use_smart=args.smart)

    # Detector configs
    cfg = {
        "sample_size": args.sample_size,
        "confidence_threshold": args.confidence,
        "payloads_directory": args.payloads_dir,
        "use_smart_bypass": args.smart,
    }

    # ---------------------------------------------------------
    # DISPATCH
    # ---------------------------------------------------------

    techniques = args.techniques

    if "error_based" in techniques:
        det = AdvancedErrorBasedDetector(cfg)
        results["error_based"] = det.scan(args.target)

    if "boolean_based" in techniques:
        det = AdvancedBooleanBasedDetector(cfg)
        results["boolean_based"] = det.scan(args.target)

    if "time_based" in techniques:
        det = AdvancedTimeBasedDetector(cfg)
        results["time_based"] = det.scan(args.target)

    if "nosql" in techniques:
        det = AdvancedNoSQLInjectionDetector(cfg)
        results["nosql"] = det.scan(args.target)

    if "union_based" in techniques:
        det = UnionBasedDetector(cfg)
        results["union_based"] = det.scan(args.target)

    if "stacked_queries" in techniques:
        det = StackedQueryDetector(cfg)
        results["stacked_queries"] = det.scan(args.target)

    if "second_order" in techniques:
        det = SecondOrderDetector(cfg)
        results["second_order"] = det.scan(args.target)

    # ---------------------------------------------------------
    # Oblique full-scan mode (aggregates all)
    # ---------------------------------------------------------
    if "oblique" in techniques:
        logger.info("[*] Running Oblique Full Scan...")
        results["error_based"] = run_error_based_scan(args.target, cfg)
        results["boolean_based"] = run_boolean_based_scan(args.target, cfg)
        results["time_based"] = run_time_based_scan(args.target, cfg)
        results["nosql"] = run_nosql_injection_scan(args.target, cfg)

    return results


# ---------------------------------------------------------
# MAIN
# ---------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="AttackVictor SQLi/NoSQLi Scanner CLI"
    )

    parser.add_argument("target", help="Target URL")

    parser.add_argument(
        "-t", "--techniques",
        nargs="+",
        default=["error_based", "boolean_based", "time_based"],
        help="Techniques: error_based boolean_based time_based nosql union_based stacked_queries second_order oblique"
    )

    parser.add_argument(
        "-s", "--strategy",
        default="quick",
        choices=list(SCAN_STRATEGIES.keys()),
        help="Scan strategy"
    )

    parser.add_argument(
        "--sample-size", type=int,
        default=ENGINE_DEFAULTS["sample_size"]
    )

    parser.add_argument(
        "--confidence", type=float,
        default=ENGINE_DEFAULTS["confidence_threshold"]
    )

    parser.add_argument(
        "--payloads-dir",
        default=ENGINE_DEFAULTS["payloads_dir"]
    )

    parser.add_argument(
        "--smart", action="store_true",
        help="Enable SmartWAF bypass engine"
    )

    parser.add_argument(
        "--verify-ssl", action="store_true",
        help="Verify SSL certificates"
    )

    parser.add_argument(
        "--output", default="scan_report.json",
        help="Save final report to file"
    )

    args = parser.parse_args()

    logger = make_logger("main")

    # ---------------------------------------------------------
    # Load target first (async)
    # ---------------------------------------------------------
    logger.info(f"[*] Loading target: {args.target}")

    try:
        target_info = asyncio.run(
            async_load_target(args.target, verify_ssl=args.verify_ssl)
        )
    except KeyboardInterrupt:
        logger.error("User aborted.")
        sys.exit(1)

    if not target_info.get("alive"):
        logger.error("[-] Target is unreachable or invalid.")
        print(target_info)
        sys.exit(1)

    logger.info(f"[+] Final URL: {target_info['final_url']}")
    logger.info(f"[+] Status: {target_info['status']}")

    # ---------------------------------------------------------
    # Run selected detectors
    # ---------------------------------------------------------
    start = time.time()
    scan_results = run_detectors(args, target_info, logger)
    scan_results["scan_start"] = time.strftime("%Y-%m-%d %H:%M:%S")
    scan_results["scan_duration"] = round(time.time() - start, 2)

    # ---------------------------------------------------------
    # Merge final report
    # ---------------------------------------------------------
    final_report = merge_scan_results(scan_results)

    path = save_report(final_report, args.output)

    logger.info(f"[✓] Report saved: {path}")
    print("\n=== SCAN SUMMARY ===")
    print("Target:", final_report["target"]["final_url"])
    print("Vulnerabilities found:", final_report["vulnerability_count"])
    print("Confidence score:", final_report["confidence_score"])
    print("Risk Level:", final_report["risk_level"])
    print("Report:", path)


if __name__ == "__main__":
    main()
