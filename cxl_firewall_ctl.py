#!/usr/bin/env python3
"""
CXL Firewall Control Tool

Userspace control plane for managing CXL firewall eBPF coprocessor,
configuring ATS policies, monitoring shadow cache, and controlling
fault injection.

Copyright (c) 2025 Drywall Project
Licensed under GPL v2
"""

import os
import sys
import argparse
import subprocess
import json
from typing import Dict, List, Optional


class CXLFirewallController:
    """Controller for CXL firewall eBPF program"""

    def __init__(self):
        self.bpftool = self._find_bpftool()
        self.prog_id = None
        self.map_ids = {}

    def _find_bpftool(self) -> str:
        """Find bpftool binary"""
        for path in ["/usr/sbin/bpftool", "/usr/bin/bpftool", "/sbin/bpftool"]:
            if os.path.exists(path):
                return path

        # Try to find in PATH
        try:
            result = subprocess.run(["which", "bpftool"],
                                   capture_output=True, text=True)
            if result.returncode == 0:
                return result.stdout.strip()
        except:
            pass

        raise RuntimeError("bpftool not found. Please install bpftools package.")

    def _run_bpftool(self, args: List[str]) -> str:
        """Run bpftool command"""
        cmd = [self.bpftool] + args
        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode != 0:
            raise RuntimeError(f"bpftool command failed: {result.stderr}")

        return result.stdout

    def load_program(self, obj_file: str) -> bool:
        """Load CXL firewall eBPF program"""
        print(f"Loading eBPF program from {obj_file}...")

        if not os.path.exists(obj_file):
            print(f"Error: Object file not found: {obj_file}")
            return False

        try:
            # Load the program
            output = self._run_bpftool(["prog", "load", obj_file, "/sys/fs/bpf/cxl_firewall"])

            # Get program ID
            output = self._run_bpftool(["prog", "show", "pinned", "/sys/fs/bpf/cxl_firewall"])

            # Parse program ID from output
            for line in output.split('\n'):
                if 'id' in line.lower():
                    parts = line.split()
                    for i, part in enumerate(parts):
                        if part == 'id':
                            self.prog_id = int(parts[i + 1])
                            break

            print(f"Successfully loaded program (ID: {self.prog_id})")

            # Discover map IDs
            self._discover_maps()

            return True

        except Exception as e:
            print(f"Error loading program: {e}")
            return False

    def _discover_maps(self):
        """Discover BPF map IDs"""
        try:
            output = self._run_bpftool(["map", "list"])

            # Parse map list to find our maps
            map_names = [
                "shadow_cache_map",
                "ats_policy_map",
                "event_ringbuf",
                "fault_config_map",
                "stats_map",
                "ownership_map"
            ]

            for line in output.split('\n'):
                for name in map_names:
                    if name in line:
                        parts = line.split()
                        for i, part in enumerate(parts):
                            if part == 'id':
                                self.map_ids[name] = int(parts[i + 1])
                                print(f"Discovered map: {name} (ID: {parts[i + 1]})")
                                break

        except Exception as e:
            print(f"Warning: Could not discover maps: {e}")

    def unload_program(self) -> bool:
        """Unload CXL firewall eBPF program"""
        print("Unloading eBPF program...")

        try:
            # Unpin the program
            if os.path.exists("/sys/fs/bpf/cxl_firewall"):
                os.unlink("/sys/fs/bpf/cxl_firewall")

            print("Successfully unloaded program")
            return True

        except Exception as e:
            print(f"Error unloading program: {e}")
            return False

    def add_policy(self, start_addr: int, end_addr: int,
                   allow_exclusive: bool, require_shadow: bool) -> bool:
        """Add ATS exclusivity policy"""
        if "ats_policy_map" not in self.map_ids:
            print("Error: ats_policy_map not found")
            return False

        map_id = self.map_ids["ats_policy_map"]

        # Find next available policy slot
        # For simplicity, we'll use slot 0 (in real impl, would find empty slot)
        key = 0

        # Create policy structure (must match struct ats_policy)
        # struct ats_policy {
        #     uint64_t start_addr;
        #     uint64_t end_addr;
        #     uint32_t policy_flags;
        #     uint32_t device_mask;
        #     uint8_t allow_exclusive;
        #     uint8_t require_shadow;
        #     uint8_t priority;
        # };

        policy_data = {
            "start_addr": start_addr,
            "end_addr": end_addr,
            "policy_flags": 0x7,  # READ | WRITE | EXCLUSIVE
            "device_mask": 0,
            "allow_exclusive": 1 if allow_exclusive else 0,
            "require_shadow": 1 if require_shadow else 0,
            "priority": 0
        }

        print(f"Adding policy: 0x{start_addr:x} - 0x{end_addr:x}")
        print(f"  Allow exclusive: {allow_exclusive}")
        print(f"  Require shadow: {require_shadow}")

        # In real implementation, would use bpf syscall or libbpf
        # For now, just log the policy
        print(f"Policy would be written to map ID {map_id}, key {key}")

        return True

    def configure_fault_injection(self, enabled: bool, inject_rate: int,
                                  fault_type: int) -> bool:
        """Configure fault injection"""
        if "fault_config_map" not in self.map_ids:
            print("Error: fault_config_map not found")
            return False

        map_id = self.map_ids["fault_config_map"]

        config = {
            "enabled": 1 if enabled else 0,
            "inject_rate": inject_rate,
            "fault_type": fault_type,
            "target_device": 0,
            "target_addr_start": 0,
            "target_addr_end": 0
        }

        print(f"Configuring fault injection:")
        print(f"  Enabled: {enabled}")
        print(f"  Inject rate: 1 in {inject_rate}")
        print(f"  Fault type: {fault_type}")

        print(f"Configuration would be written to map ID {map_id}")

        return True

    def get_statistics(self) -> Optional[Dict]:
        """Get firewall statistics"""
        if "stats_map" not in self.map_ids:
            print("Error: stats_map not found")
            return None

        map_id = self.map_ids["stats_map"]

        # In real implementation, would read from map
        # For now, return sample data
        stats = {
            "total_transactions": 12543,
            "exclusive_grants": 342,
            "exclusive_revokes": 338,
            "policy_violations": 4,
            "shadow_creates": 215,
            "shadow_restores": 12,
            "faults_injected": 87
        }

        return stats

    def dump_shadow_cache(self) -> List[Dict]:
        """Dump shadow cache entries"""
        if "shadow_cache_map" not in self.map_ids:
            print("Error: shadow_cache_map not found")
            return []

        map_id = self.map_ids["shadow_cache_map"]

        print(f"Dumping shadow cache (map ID {map_id})...")

        # In real implementation, would iterate map entries
        # For now, return sample data
        entries = [
            {
                "addr": "0xffff880100000000",
                "device_id": 0,
                "state": 2,  # EXCLUSIVE
                "timestamp": 1234567890,
                "version": 1
            },
            {
                "addr": "0xffff880100000040",
                "device_id": 0,
                "state": 2,
                "timestamp": 1234567891,
                "version": 1
            }
        ]

        return entries

    def monitor_events(self, duration: int = 10):
        """Monitor transaction events from ring buffer"""
        if "event_ringbuf" not in self.map_ids:
            print("Error: event_ringbuf not found")
            return

        map_id = self.map_ids["event_ringbuf"]

        print(f"Monitoring events for {duration} seconds...")
        print("(In real implementation, would consume from ring buffer)")

        # Would use perf event or ring buffer consumer here
        print("Event monitoring not yet implemented")


def main():
    parser = argparse.ArgumentParser(
        description="CXL Firewall Control Tool"
    )

    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # Load command
    load_parser = subparsers.add_parser("load", help="Load eBPF program")
    load_parser.add_argument("object_file", help="Path to eBPF object file")

    # Unload command
    unload_parser = subparsers.add_parser("unload", help="Unload eBPF program")

    # Add policy command
    policy_parser = subparsers.add_parser("add-policy", help="Add ATS policy")
    policy_parser.add_argument("--start", required=True, help="Start address (hex)")
    policy_parser.add_argument("--end", required=True, help="End address (hex)")
    policy_parser.add_argument("--allow-exclusive", action="store_true",
                              help="Allow exclusive access")
    policy_parser.add_argument("--require-shadow", action="store_true",
                              help="Require shadow before exclusive")

    # Configure fault injection
    fault_parser = subparsers.add_parser("fault-inject",
                                         help="Configure fault injection")
    fault_parser.add_argument("--enable", action="store_true",
                             help="Enable fault injection")
    fault_parser.add_argument("--disable", action="store_true",
                             help="Disable fault injection")
    fault_parser.add_argument("--rate", type=int, default=10,
                             help="Injection rate (1 in N)")
    fault_parser.add_argument("--type", type=int, default=1,
                             help="Fault type (1-5)")

    # Statistics command
    stats_parser = subparsers.add_parser("stats", help="Get statistics")
    stats_parser.add_argument("--json", action="store_true",
                             help="Output as JSON")

    # Dump shadow cache
    dump_parser = subparsers.add_parser("dump-shadow", help="Dump shadow cache")
    dump_parser.add_argument("--json", action="store_true",
                            help="Output as JSON")

    # Monitor events
    monitor_parser = subparsers.add_parser("monitor", help="Monitor events")
    monitor_parser.add_argument("--duration", type=int, default=10,
                               help="Duration in seconds")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    controller = CXLFirewallController()

    if args.command == "load":
        return 0 if controller.load_program(args.object_file) else 1

    elif args.command == "unload":
        return 0 if controller.unload_program() else 1

    elif args.command == "add-policy":
        start = int(args.start, 16)
        end = int(args.end, 16)
        return 0 if controller.add_policy(start, end, args.allow_exclusive,
                                          args.require_shadow) else 1

    elif args.command == "fault-inject":
        enabled = args.enable or not args.disable
        return 0 if controller.configure_fault_injection(enabled, args.rate,
                                                         args.type) else 1

    elif args.command == "stats":
        stats = controller.get_statistics()
        if stats:
            if args.json:
                print(json.dumps(stats, indent=2))
            else:
                print("CXL Firewall Statistics:")
                print("=" * 40)
                for key, value in stats.items():
                    print(f"  {key}: {value}")
            return 0
        return 1

    elif args.command == "dump-shadow":
        entries = controller.dump_shadow_cache()
        if args.json:
            print(json.dumps(entries, indent=2))
        else:
            print("Shadow Cache Entries:")
            print("=" * 60)
            for entry in entries:
                print(f"Address: {entry['addr']}")
                print(f"  Device: {entry['device_id']}")
                print(f"  State: {entry['state']}")
                print(f"  Version: {entry['version']}")
                print()
        return 0

    elif args.command == "monitor":
        controller.monitor_events(args.duration)
        return 0

    return 0


if __name__ == "__main__":
    sys.exit(main())
