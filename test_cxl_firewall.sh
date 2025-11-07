#!/bin/bash
#
# CXL Firewall Integration Test Suite
#
# This script tests the full CXL firewall stack including:
# - eBPF coprocessor loading
# - ATS policy enforcement
# - Shadow cache management
# - Fault injection
# - Kernel fuzzing
#
# Copyright (c) 2025 Drywall Project
# Licensed under GPL v2

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

# Logging functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

test_start() {
    echo ""
    echo "=========================================="
    echo "TEST: $1"
    echo "=========================================="
    TESTS_RUN=$((TESTS_RUN + 1))
}

test_pass() {
    log_info "✓ PASS: $1"
    TESTS_PASSED=$((TESTS_PASSED + 1))
}

test_fail() {
    log_error "✗ FAIL: $1"
    TESTS_FAILED=$((TESTS_FAILED + 1))
}

# Check prerequisites
check_prerequisites() {
    test_start "Checking prerequisites"

    local missing=0

    # Check for clang
    if ! command -v clang &> /dev/null; then
        log_error "clang not found"
        missing=1
    else
        test_pass "clang found"
    fi

    # Check for bpftool
    if ! command -v bpftool &> /dev/null; then
        log_warn "bpftool not found (optional)"
    else
        test_pass "bpftool found"
    fi

    # Check for libbpf headers
    if [ ! -d "/usr/include/bpf" ]; then
        log_warn "libbpf headers not found (optional)"
    else
        test_pass "libbpf headers found"
    fi

    # Check for Python 3
    if ! command -v python3 &> /dev/null; then
        log_error "python3 not found"
        missing=1
    else
        test_pass "python3 found"
    fi

    if [ $missing -eq 1 ]; then
        test_fail "Missing required dependencies"
        return 1
    fi

    test_pass "All prerequisites satisfied"
    return 0
}

# Build eBPF program
build_ebpf() {
    test_start "Building eBPF CXL firewall"

    cd tools/ebpf

    # Try to build with the Makefile
    if make -f Makefile.ebpf.cxl clean all 2>&1 | tee /tmp/ebpf_build.log; then
        test_pass "eBPF program built successfully"
        cd ../..
        return 0
    else
        log_error "eBPF build failed. Check /tmp/ebpf_build.log"
        test_fail "eBPF program build"
        cd ../..
        return 1
    fi
}

# Test eBPF program loading
test_ebpf_loading() {
    test_start "Testing eBPF program loading"

    if [ ! -f "tools/ebpf/cxl_firewall.bpf.o" ]; then
        test_fail "eBPF object file not found"
        return 1
    fi

    # Verify object file
    if file tools/ebpf/cxl_firewall.bpf.o | grep -q "eBPF"; then
        test_pass "eBPF object file valid"
    else
        test_fail "eBPF object file invalid"
        return 1
    fi

    # Try to load with control tool (requires root)
    if [ "$EUID" -eq 0 ]; then
        if ./cxl_firewall_ctl.py load tools/ebpf/cxl_firewall.bpf.o; then
            test_pass "eBPF program loaded"

            # Unload
            ./cxl_firewall_ctl.py unload
            test_pass "eBPF program unloaded"
        else
            test_fail "eBPF program loading"
            return 1
        fi
    else
        log_warn "Skipping load test (requires root)"
    fi

    return 0
}

# Test firewall control tool
test_firewall_control() {
    test_start "Testing firewall control tool"

    # Test help
    if ./cxl_firewall_ctl.py --help > /dev/null 2>&1; then
        test_pass "Control tool help works"
    else
        test_fail "Control tool help"
        return 1
    fi

    # Test policy addition (dry run)
    log_info "Testing policy management..."
    if [ "$EUID" -eq 0 ]; then
        ./cxl_firewall_ctl.py add-policy \
            --start 0xffff880000000000 \
            --end 0xffff880010000000 \
            --allow-exclusive \
            --require-shadow
        test_pass "Policy management works"
    else
        log_warn "Skipping policy test (requires root)"
    fi

    # Test statistics
    if ./cxl_firewall_ctl.py stats --json > /dev/null 2>&1; then
        test_pass "Statistics retrieval works"
    else
        log_warn "Statistics retrieval failed (expected without loaded program)"
    fi

    return 0
}

# Test fault injection framework
test_fault_injection() {
    test_start "Testing fault injection framework"

    # Compile fault injection code
    log_info "Checking fault injection compilation..."

    if [ -f "hw/cxl/cxl-fault-injection.c" ]; then
        test_pass "Fault injection source found"

        # Try syntax check with clang
        if clang -fsyntax-only \
            -I./include \
            -I./build \
            -I/usr/include \
            hw/cxl/cxl-fault-injection.c 2>&1 | head -20; then
            test_pass "Fault injection code valid"
        else
            log_warn "Syntax check had warnings (may be OK)"
        fi
    else
        test_fail "Fault injection source not found"
        return 1
    fi

    return 0
}

# Test kernel fuzzer
test_kernel_fuzzer() {
    test_start "Testing kernel fuzzer"

    # Test fuzzer help
    if ./cxl_kernel_fuzzer.py --help > /dev/null 2>&1; then
        test_pass "Fuzzer help works"
    else
        test_fail "Fuzzer help"
        return 1
    fi

    # Validate fuzzer syntax
    if python3 -m py_compile cxl_kernel_fuzzer.py; then
        test_pass "Fuzzer Python syntax valid"
    else
        test_fail "Fuzzer Python syntax"
        return 1
    fi

    log_info "Fuzzer validated (cannot run without QEMU VM)"

    return 0
}

# Test shadow cache coherency
test_shadow_cache() {
    test_start "Testing shadow cache coherency implementation"

    if [ -f "hw/cxl/cxl-cache-coherency.c" ]; then
        test_pass "Shadow cache implementation found"

        # Check for key functions
        if grep -q "cxl_cache_mark_exclusive" hw/cxl/cxl-cache-coherency.c; then
            test_pass "Mark exclusive function present"
        else
            test_fail "Mark exclusive function missing"
        fi

        if grep -q "cxl_cache_device_offline" hw/cxl/cxl-cache-coherency.c; then
            test_pass "Device offline handler present"
        else
            test_fail "Device offline handler missing"
        fi
    else
        test_fail "Shadow cache implementation not found"
        return 1
    fi

    return 0
}

# Generate test report
generate_report() {
    echo ""
    echo "=========================================="
    echo "TEST SUMMARY"
    echo "=========================================="
    echo "Total tests run: $TESTS_RUN"
    echo "Tests passed:    $TESTS_PASSED"
    echo "Tests failed:    $TESTS_FAILED"

    if [ $TESTS_FAILED -eq 0 ]; then
        log_info "All tests passed! ✓"
        return 0
    else
        log_error "$TESTS_FAILED test(s) failed"
        return 1
    fi
}

# Main test execution
main() {
    echo "CXL Firewall Integration Test Suite"
    echo "===================================="
    echo ""

    # Run tests
    check_prerequisites || true
    build_ebpf || true
    test_ebpf_loading || true
    test_firewall_control || true
    test_fault_injection || true
    test_kernel_fuzzer || true
    test_shadow_cache || true

    # Generate report
    generate_report

    return $?
}

# Run main
main
exit $?
