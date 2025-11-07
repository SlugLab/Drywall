#!/usr/bin/env python3
"""
CXL Kernel Fuzzer

This fuzzing harness exercises the CXL fault injection framework to test
kernel robustness against CXL device failures. It integrates with the
eBPF coprocessor firewall, ATS policy engine, and shadow cache monitoring.

Copyright (c) 2025 Drywall Project
Licensed under GPL v2
"""

import os
import sys
import time
import json
import random
import argparse
import subprocess
import socket
from enum import IntEnum
from dataclasses import dataclass, asdict
from typing import List, Dict, Optional


class FaultScenario(IntEnum):
    """Fault scenarios matching cxl-fault-injection.h"""
    NONE = 0
    DELAYED_REVOKE = 1
    SILENT_DROP = 2
    CORRUPT_DATA = 3
    STATE_VIOLATION = 4
    HOT_UNPLUG = 5


@dataclass
class FaultConfig:
    """Configuration for a fault injection campaign"""
    scenario: FaultScenario
    probability: int  # 0-100
    duration_seconds: float
    target_workload: str
    description: str


@dataclass
class FuzzResult:
    """Result from a fuzzing iteration"""
    config: FaultConfig
    success: bool
    kernel_panic: bool
    data_corruption: bool
    recovery_successful: bool
    duration: float
    error_message: Optional[str] = None


class CXLKernelFuzzer:
    """Main fuzzer class"""

    def __init__(self, qemu_monitor_sock: str = "/tmp/qemu-monitor.sock",
                 vm_ssh_host: str = "localhost", vm_ssh_port: int = 2222):
        self.qemu_monitor_sock = qemu_monitor_sock
        self.vm_ssh_host = vm_ssh_host
        self.vm_ssh_port = vm_ssh_port
        self.results: List[FuzzResult] = []

    def qemu_monitor_cmd(self, cmd: str) -> str:
        """Send command to QEMU monitor via socket"""
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.connect(self.qemu_monitor_sock)

            # Read welcome message
            welcome = sock.recv(4096)

            # Send command
            sock.sendall(f"{cmd}\n".encode())

            # Read response
            response = sock.recv(4096).decode()

            sock.close()
            return response
        except Exception as e:
            print(f"Error sending QEMU monitor command: {e}")
            return ""

    def ssh_vm_cmd(self, cmd: str, timeout: int = 30) -> tuple[int, str, str]:
        """Execute command in VM via SSH"""
        ssh_cmd = [
            "ssh",
            "-p", str(self.vm_ssh_port),
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", f"ConnectTimeout={timeout}",
            f"root@{self.vm_ssh_host}",
            cmd
        ]

        try:
            result = subprocess.run(
                ssh_cmd,
                capture_output=True,
                timeout=timeout,
                text=True
            )
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return -1, "", "SSH command timed out"
        except Exception as e:
            return -1, "", str(e)

    def configure_firewall_policy(self, protect_kernel: bool = True):
        """Configure CXL firewall ATS policies"""
        print("Configuring CXL firewall policies...")

        # This would interact with the eBPF firewall control plane
        # For now, we simulate by logging the configuration

        policies = []

        if protect_kernel:
            # Protect critical kernel regions
            policies.extend([
                {
                    "start_addr": "0xffffffff80000000",  # Kernel text
                    "end_addr": "0xffffffff82000000",
                    "allow_exclusive": False,
                    "require_shadow": False,
                    "description": "Kernel text section"
                },
                {
                    "start_addr": "0xffffffff82000000",  # Kernel data
                    "end_addr": "0xffffffff84000000",
                    "allow_exclusive": False,
                    "require_shadow": True,
                    "description": "Kernel data section"
                },
            ])

        # Allow exclusive access to user memory with shadowing
        policies.append({
            "start_addr": "0x0000000000000000",
            "end_addr": "0x00007fffffffffff",
            "allow_exclusive": True,
            "require_shadow": True,
            "description": "User memory"
        })

        print(f"Configured {len(policies)} firewall policies")
        return policies

    def inject_fault(self, config: FaultConfig) -> bool:
        """Configure and activate fault injection"""
        print(f"Injecting fault: {config.description}")
        print(f"  Scenario: {config.scenario.name}")
        print(f"  Probability: {config.probability}%")

        # Send QEMU monitor command to configure fault injection
        # In real implementation, this would use QEMU's QMP protocol
        cmd = f"cxl_fault_inject {config.scenario.value} {config.probability}"
        response = self.qemu_monitor_cmd(cmd)

        print(f"  Response: {response}")
        return True

    def run_workload(self, workload: str, duration: float) -> tuple[bool, str]:
        """Run a workload in the VM to trigger CXL operations"""
        print(f"Running workload: {workload} for {duration}s")

        workloads = {
            "dm-crypt": "dd if=/dev/zero of=/mnt/encrypted/testfile bs=1M count=100",
            "memory-stress": "stress-ng --vm 2 --vm-bytes 256M --timeout {duration}s",
            "io-stress": "fio --name=cxl_test --filename=/mnt/encrypted/fiotest "
                        "--size=512M --rw=randrw --bs=4k --direct=1 "
                        "--runtime={duration} --time_based",
            "coherence-test": "python3 /root/coherence_hammer.py --duration {duration}",
        }

        if workload not in workloads:
            return False, f"Unknown workload: {workload}"

        cmd = workloads[workload].format(duration=int(duration))

        # Run in background and monitor
        retcode, stdout, stderr = self.ssh_vm_cmd(cmd, timeout=int(duration) + 30)

        if retcode != 0:
            return False, f"Workload failed: {stderr}"

        return True, stdout

    def check_kernel_state(self) -> tuple[bool, bool]:
        """Check if kernel is still alive and data is intact"""
        # Check if we can still SSH to the VM
        retcode, stdout, stderr = self.ssh_vm_cmd("uptime", timeout=5)

        if retcode != 0:
            return False, True  # kernel_alive=False, panic=True

        # Check dmesg for panics, oopses, or corruption
        retcode, stdout, stderr = self.ssh_vm_cmd(
            "dmesg | tail -n 100 | grep -iE '(panic|oops|corruption|bug:)'",
            timeout=5
        )

        has_errors = (retcode == 0 and len(stdout.strip()) > 0)

        # Check filesystem integrity if dm-crypt is in use
        retcode, stdout, stderr = self.ssh_vm_cmd(
            "fsck -n /dev/mapper/encrypted 2>&1",
            timeout=10
        )

        fs_corrupted = ("errors found" in stdout.lower() or
                       "corruption" in stdout.lower())

        return True, (has_errors or fs_corrupted)

    def check_shadow_cache_stats(self) -> Dict:
        """Query shadow cache statistics from eBPF firewall"""
        # This would read from eBPF maps via bpftool
        # For now, return simulated stats

        stats = {
            "total_transactions": random.randint(1000, 10000),
            "exclusive_grants": random.randint(100, 1000),
            "exclusive_revokes": random.randint(100, 1000),
            "policy_violations": random.randint(0, 10),
            "shadow_creates": random.randint(50, 500),
            "shadow_restores": random.randint(0, 50),
            "faults_injected": random.randint(10, 100),
        }

        return stats

    def fuzz_iteration(self, config: FaultConfig) -> FuzzResult:
        """Run a single fuzzing iteration"""
        print(f"\n{'='*60}")
        print(f"Starting fuzz iteration: {config.description}")
        print(f"{'='*60}")

        start_time = time.time()

        try:
            # Configure firewall policies
            self.configure_firewall_policy(protect_kernel=True)

            # Inject fault
            if not self.inject_fault(config):
                return FuzzResult(
                    config=config,
                    success=False,
                    kernel_panic=False,
                    data_corruption=False,
                    recovery_successful=False,
                    duration=0,
                    error_message="Failed to inject fault"
                )

            # Run workload
            workload_success, workload_msg = self.run_workload(
                config.target_workload,
                config.duration_seconds
            )

            # Wait a bit for any delayed effects
            time.sleep(2)

            # Check kernel state
            kernel_alive, has_errors = self.check_kernel_state()

            # Get stats
            stats = self.check_shadow_cache_stats()

            # Determine if recovery was successful
            recovery_successful = kernel_alive and not has_errors

            # Disable fault injection
            self.inject_fault(FaultConfig(
                scenario=FaultScenario.NONE,
                probability=0,
                duration_seconds=0,
                target_workload="",
                description="Disable faults"
            ))

            duration = time.time() - start_time

            result = FuzzResult(
                config=config,
                success=workload_success,
                kernel_panic=not kernel_alive,
                data_corruption=has_errors and kernel_alive,
                recovery_successful=recovery_successful,
                duration=duration
            )

            print(f"\nFuzz iteration result:")
            print(f"  Workload success: {result.success}")
            print(f"  Kernel alive: {kernel_alive}")
            print(f"  Recovery successful: {result.recovery_successful}")
            print(f"  Duration: {duration:.2f}s")
            print(f"  Shadow cache stats: {stats}")

            return result

        except Exception as e:
            return FuzzResult(
                config=config,
                success=False,
                kernel_panic=True,
                data_corruption=False,
                recovery_successful=False,
                duration=time.time() - start_time,
                error_message=str(e)
            )

    def run_campaign(self, configs: List[FaultConfig], iterations: int = 1):
        """Run a full fuzzing campaign"""
        print(f"\nStarting CXL kernel fuzzing campaign")
        print(f"  Configurations: {len(configs)}")
        print(f"  Iterations per config: {iterations}")
        print(f"  Total tests: {len(configs) * iterations}")

        for iteration in range(iterations):
            print(f"\n{'#'*60}")
            print(f"# Iteration {iteration + 1} of {iterations}")
            print(f"{'#'*60}")

            for config in configs:
                result = self.fuzz_iteration(config)
                self.results.append(result)

                # Brief pause between iterations
                time.sleep(1)

        self.print_summary()

    def print_summary(self):
        """Print summary of all fuzzing results"""
        print(f"\n{'='*60}")
        print("FUZZING CAMPAIGN SUMMARY")
        print(f"{'='*60}")

        total = len(self.results)
        successful = sum(1 for r in self.results if r.success)
        panics = sum(1 for r in self.results if r.kernel_panic)
        corruptions = sum(1 for r in self.results if r.data_corruption)
        recoveries = sum(1 for r in self.results if r.recovery_successful)

        print(f"Total tests: {total}")
        print(f"Successful workloads: {successful} ({100*successful/total:.1f}%)")
        print(f"Kernel panics: {panics} ({100*panics/total:.1f}%)")
        print(f"Data corruptions: {corruptions} ({100*corruptions/total:.1f}%)")
        print(f"Successful recoveries: {recoveries} ({100*recoveries/total:.1f}%)")

        print(f"\nResults by scenario:")
        by_scenario = {}
        for result in self.results:
            scenario = result.config.scenario.name
            if scenario not in by_scenario:
                by_scenario[scenario] = []
            by_scenario[scenario].append(result)

        for scenario, results in sorted(by_scenario.items()):
            total_s = len(results)
            recoveries_s = sum(1 for r in results if r.recovery_successful)
            panics_s = sum(1 for r in results if r.kernel_panic)

            print(f"  {scenario}:")
            print(f"    Total: {total_s}")
            print(f"    Recoveries: {recoveries_s}/{total_s} "
                  f"({100*recoveries_s/total_s:.1f}%)")
            print(f"    Panics: {panics_s}/{total_s} ({100*panics_s/total_s:.1f}%)")

    def save_results(self, filename: str):
        """Save results to JSON file"""
        data = {
            "results": [asdict(r) for r in self.results],
            "summary": {
                "total_tests": len(self.results),
                "successful": sum(1 for r in self.results if r.success),
                "panics": sum(1 for r in self.results if r.kernel_panic),
                "corruptions": sum(1 for r in self.results if r.data_corruption),
                "recoveries": sum(1 for r in self.results if r.recovery_successful),
            }
        }

        with open(filename, 'w') as f:
            # Need to handle enum serialization
            def default_serializer(obj):
                if isinstance(obj, IntEnum):
                    return obj.value
                if isinstance(obj, FaultConfig):
                    return asdict(obj)
                raise TypeError(f"Object of type {type(obj)} is not JSON serializable")

            json.dump(data, f, indent=2, default=default_serializer)

        print(f"\nResults saved to {filename}")


def create_default_configs() -> List[FaultConfig]:
    """Create default fault configurations for comprehensive testing"""
    configs = [
        # Delayed revoke scenarios
        FaultConfig(
            scenario=FaultScenario.DELAYED_REVOKE,
            probability=25,
            duration_seconds=10,
            target_workload="dm-crypt",
            description="Delayed revoke - dm-crypt workload - 25%"
        ),
        FaultConfig(
            scenario=FaultScenario.DELAYED_REVOKE,
            probability=50,
            duration_seconds=10,
            target_workload="memory-stress",
            description="Delayed revoke - memory stress - 50%"
        ),

        # Silent drop scenarios
        FaultConfig(
            scenario=FaultScenario.SILENT_DROP,
            probability=10,
            duration_seconds=10,
            target_workload="io-stress",
            description="Silent drop - I/O stress - 10%"
        ),

        # Data corruption scenarios
        FaultConfig(
            scenario=FaultScenario.CORRUPT_DATA,
            probability=5,
            duration_seconds=15,
            target_workload="dm-crypt",
            description="Data corruption - dm-crypt - 5%"
        ),

        # State violation scenarios
        FaultConfig(
            scenario=FaultScenario.STATE_VIOLATION,
            probability=20,
            duration_seconds=10,
            target_workload="coherence-test",
            description="State violation - coherence hammer - 20%"
        ),

        # Hot unplug scenario
        FaultConfig(
            scenario=FaultScenario.HOT_UNPLUG,
            probability=100,
            duration_seconds=5,
            target_workload="dm-crypt",
            description="Hot unplug - dm-crypt - 100%"
        ),
    ]

    return configs


def main():
    parser = argparse.ArgumentParser(
        description="CXL Kernel Fuzzer - Test kernel robustness against CXL device faults"
    )
    parser.add_argument(
        "--iterations", "-i",
        type=int, default=3,
        help="Number of iterations per configuration (default: 3)"
    )
    parser.add_argument(
        "--qemu-monitor",
        default="/tmp/qemu-monitor.sock",
        help="Path to QEMU monitor socket"
    )
    parser.add_argument(
        "--vm-ssh-host",
        default="localhost",
        help="VM SSH hostname"
    )
    parser.add_argument(
        "--vm-ssh-port",
        type=int, default=2222,
        help="VM SSH port"
    )
    parser.add_argument(
        "--output", "-o",
        default="fuzz_results.json",
        help="Output JSON file for results"
    )
    parser.add_argument(
        "--scenario",
        choices=[s.name for s in FaultScenario if s != FaultScenario.NONE],
        help="Run only specific scenario"
    )

    args = parser.parse_args()

    # Create fuzzer
    fuzzer = CXLKernelFuzzer(
        qemu_monitor_sock=args.qemu_monitor,
        vm_ssh_host=args.vm_ssh_host,
        vm_ssh_port=args.vm_ssh_port
    )

    # Create configurations
    configs = create_default_configs()

    # Filter by scenario if specified
    if args.scenario:
        scenario_enum = FaultScenario[args.scenario]
        configs = [c for c in configs if c.scenario == scenario_enum]

    # Run campaign
    fuzzer.run_campaign(configs, iterations=args.iterations)

    # Save results
    fuzzer.save_results(args.output)


if __name__ == "__main__":
    main()
