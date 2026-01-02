#!/usr/bin/env python3
"""
Test Runner for AWS CSPM

This script provides an easy way to run all tests for the CSPM system
with proper environment setup and reporting.
"""

import argparse
import os
import sys
import subprocess
from pathlib import Path


def run_unit_tests(verbose=False, coverage=False):
    """Run unit tests."""
    print("🧪 Running Unit Tests...")
    
    cmd = [sys.executable, "-m", "pytest"]
    
    if verbose:
        cmd.append("-v")
    
    if coverage:
        cmd.extend(["--cov=src", "--cov-report=html", "--cov-report=term-missing"])
    
    cmd.extend([
        "tests/",
        "--tb=short",
        "-m", "not slow"
    ])
    
    result = subprocess.run(cmd, cwd=Path(__file__).parent)
    return result.returncode == 0


def run_integration_tests(verbose=False):
    """Run integration tests."""
    print("🔗 Running Integration Tests...")
    
    cmd = [sys.executable, "-m", "pytest"]
    
    if verbose:
        cmd.append("-v")
    
    cmd.extend([
        "tests/",
        "--tb=short",
        "-m", "integration"
    ])
    
    result = subprocess.run(cmd, cwd=Path(__file__).parent)
    return result.returncode == 0


def run_performance_tests(verbose=False):
    """Run performance tests."""
    print("⚡ Running Performance Tests...")
    
    cmd = [sys.executable, "-m", "pytest"]
    
    if verbose:
        cmd.append("-v")
    
    cmd.extend([
        "tests/",
        "--tb=short",
        "-m", "slow"
    ])
    
    result = subprocess.run(cmd, cwd=Path(__file__).parent)
    return result.returncode == 0


def run_linting():
    """Run code linting."""
    print("🔍 Running Code Linting...")
    
    # Check if flake8 is available
    try:
        cmd = [sys.executable, "-m", "flake8", "src/", "tests/"]
        result = subprocess.run(cmd, cwd=Path(__file__).parent)
        return result.returncode == 0
    except FileNotFoundError:
        print("⚠️ flake8 not found, skipping linting")
        return True


def run_type_checking():
    """Run type checking."""
    print("📝 Running Type Checking...")
    
    # Check if mypy is available
    try:
        cmd = [sys.executable, "-m", "mypy", "src/"]
        result = subprocess.run(cmd, cwd=Path(__file__).parent)
        return result.returncode == 0
    except FileNotFoundError:
        print("⚠️ mypy not found, skipping type checking")
        return True


def run_security_scan():
    """Run security scanning."""
    print("🔒 Running Security Scan...")
    
    # Check if bandit is available
    try:
        cmd = [sys.executable, "-m", "bandit", "-r", "src/"]
        result = subprocess.run(cmd, cwd=Path(__file__).parent)
        return result.returncode == 0
    except FileNotFoundError:
        print("⚠️ bandit not found, skipping security scan")
        return True


def main():
    """Main test runner function."""
    parser = argparse.ArgumentParser(description="AWS CSPM Test Runner")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument("--coverage", "-c", action="store_true", help="Generate coverage report")
    parser.add_argument("--unit", action="store_true", help="Run only unit tests")
    parser.add_argument("--integration", action="store_true", help="Run only integration tests")
    parser.add_argument("--performance", action="store_true", help="Run only performance tests")
    parser.add_argument("--lint", action="store_true", help="Run only linting")
    parser.add_argument("--type-check", action="store_true", help="Run only type checking")
    parser.add_argument("--security", action="store_true", help="Run only security scanning")
    parser.add_argument("--all", action="store_true", help="Run all tests and checks")
    
    args = parser.parse_args()
    
    # Ensure we're in the correct directory
    project_root = Path(__file__).parent
    os.chdir(project_root)
    
    # Add project root to Python path
    sys.path.insert(0, str(project_root))
    
    results = []
    
    if args.unit or args.all or not any([args.unit, args.integration, args.performance, args.lint, args.type_check, args.security]):
        results.append(("Unit Tests", run_unit_tests(args.verbose, args.coverage)))
    
    if args.integration or args.all:
        results.append(("Integration Tests", run_integration_tests(args.verbose)))
    
    if args.performance or args.all:
        results.append(("Performance Tests", run_performance_tests(args.verbose)))
    
    if args.lint or args.all:
        results.append(("Linting", run_linting()))
    
    if args.type_check or args.all:
        results.append(("Type Checking", run_type_checking()))
    
    if args.security or args.all:
        results.append(("Security Scan", run_security_scan()))
    
    # Print results summary
    print("\n" + "="*50)
    print("📊 Test Results Summary")
    print("="*50)
    
    all_passed = True
    for test_name, passed in results:
        status = "✅ PASSED" if passed else "❌ FAILED"
        print(f"{test_name:<20} {status}")
        if not passed:
            all_passed = False
    
    if all_passed:
        print("\n🎉 All tests passed!")
        sys.exit(0)
    else:
        print("\n💥 Some tests failed!")
        sys.exit(1)


if __name__ == "__main__":
    main()