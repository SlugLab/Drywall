#!/bin/bash
# CXL Device Hot Unplug/Plug Test Script
# This script demonstrates hot removal and insertion of CXL devices

set -e

COLOR_GREEN='\033[0;32m'
COLOR_YELLOW='\033[1;33m'
COLOR_RED='\033[0;31m'
COLOR_BLUE='\033[0;34m'
COLOR_NC='\033[0m'

log_info() {
    echo -e "${COLOR_GREEN}[INFO]${COLOR_NC} $1"
}

log_warn() {
    echo -e "${COLOR_YELLOW}[WARN]${COLOR_NC} $1"
}

log_error() {
    echo -e "${COLOR_RED}[ERROR]${COLOR_NC} $1"
}

log_step() {
    echo -e "${COLOR_BLUE}[STEP]${COLOR_NC} $1"
}

# Configuration
QEMU_MONITOR_PORT=${QEMU_MONITOR_PORT:-1234}
CXL_DEVICE_ID=${CXL_DEVICE_ID:-"cxl-type1-0"}
CXL_BUS=${CXL_BUS:-"root_port13"}
CXL_MEMDEV=${CXL_MEMDEV:-"cxl-mem1"}
CXL_LSA=${CXL_LSA:-"cxl-lsa1"}

echo "╔════════════════════════════════════════════════════════════╗"
echo "║        CXL Device Hot Unplug/Plug Test                     ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo

# Function to send QEMU monitor command
qemu_monitor_cmd() {
    local CMD="$1"
    echo "$CMD" | nc localhost $QEMU_MONITOR_PORT
}

# Function to check if QEMU monitor is accessible
check_monitor() {
    log_step "Checking QEMU monitor connection..."
    if ! echo "info version" | nc -w 2 localhost $QEMU_MONITOR_PORT &>/dev/null; then
        log_error "Cannot connect to QEMU monitor on port $QEMU_MONITOR_PORT"
        log_info "Make sure QEMU is running with: -monitor tcp:127.0.0.1:$QEMU_MONITOR_PORT,server,nowait"
        exit 1
    fi
    log_info "QEMU monitor connected"
}

# Function to show current PCI devices
show_pci_devices() {
    log_step "Current PCI devices:"
    qemu_monitor_cmd "info pci" | grep -A 3 "CXL\|cxl" || echo "  No CXL devices found"
}

# Function to show QOM tree
show_qom_tree() {
    log_step "QOM device tree (CXL devices):"
    qemu_monitor_cmd "info qom-tree" | grep -A 5 -B 2 "cxl" || echo "  No CXL devices in QOM tree"
}

# Function to hot unplug CXL device
hot_unplug() {
    log_step "Hot unplugging CXL device..."

    # First, try to remove the device
    log_info "Removing CXL device: $CXL_DEVICE_ID"
    qemu_monitor_cmd "device_del $CXL_DEVICE_ID"

    sleep 2

    log_info "Device removal initiated"
    show_pci_devices
}

# Function to hot plug CXL device
hot_plug() {
    log_step "Hot plugging CXL device..."

    # Add the device back
    log_info "Adding CXL device: $CXL_DEVICE_ID"

    # For CXL Type1 device
    local CMD="device_add cxl-type1,id=$CXL_DEVICE_ID,bus=$CXL_BUS,memdev=$CXL_MEMDEV,lsa=$CXL_LSA"

    qemu_monitor_cmd "$CMD"

    sleep 2

    log_info "Device addition completed"
    show_pci_devices
}

# Function to inject PCIe error
inject_pcie_error() {
    log_step "Injecting PCIe AER (Advanced Error Reporting) error..."

    # Inject correctable error
    log_info "Injecting correctable error..."
    qemu_monitor_cmd "pcie_aer_inject_error -c -e COR_INTERNAL bus=pcie.0,device=0,function=0"

    sleep 1

    # Inject uncorrectable non-fatal error
    log_info "Injecting uncorrectable non-fatal error..."
    qemu_monitor_cmd "pcie_aer_inject_error -u -e UNCOR_UNSUPPORTED bus=pcie.0,device=0,function=0"
}

# Function to inject CXL-specific error
inject_cxl_error() {
    log_step "Injecting CXL-specific memory error..."

    # Use HMP command to inject memory error
    log_info "Injecting CXL memory error..."
    qemu_monitor_cmd "cxl-inject-poison 0x0 0x40"
}

# Function to simulate link down
simulate_link_down() {
    log_step "Simulating CXL link down..."

    # Set link status to down
    log_info "Setting link status to down for CXL device..."
    qemu_monitor_cmd "set_link $CXL_DEVICE_ID off"

    sleep 1
    log_info "Link down simulated"
}

# Function to simulate link up
simulate_link_up() {
    log_step "Simulating CXL link up..."

    # Set link status to up
    log_info "Setting link status to up for CXL device..."
    qemu_monitor_cmd "set_link $CXL_DEVICE_ID on"

    sleep 1
    log_info "Link up simulated"
}

# Function to show monitor help
show_monitor_help() {
    log_step "Available QEMU monitor commands for CXL:"
    echo "
Device Management:
  info pci                           - Show PCI devices
  info qtree                         - Show device tree
  info qom-tree                      - Show QOM object tree
  device_del <id>                    - Remove device
  device_add <type>,<params>         - Add device

CXL-Specific:
  cxl-inject-poison <addr> <size>    - Inject poison error
  cxl-inject-uncorrectable-error     - Inject uncorrectable error
  cxl-inject-correctable-error       - Inject correctable error

PCIe AER:
  pcie_aer_inject_error <params>     - Inject PCIe AER error

Link Control:
  set_link <id> on|off               - Set link status
"
}

# Main menu
show_menu() {
    echo
    echo "═══════════════════════════════════════════════════════════"
    echo "  CXL Hot Unplug/Plug Test Menu"
    echo "═══════════════════════════════════════════════════════════"
    echo "  1) Show current PCI devices"
    echo "  2) Show QOM device tree"
    echo "  3) Hot unplug CXL device"
    echo "  4) Hot plug CXL device"
    echo "  5) Inject PCIe AER error"
    echo "  6) Inject CXL memory error"
    echo "  7) Simulate link down"
    echo "  8) Simulate link up"
    echo "  9) Run full hot unplug/plug cycle"
    echo " 10) Show monitor commands help"
    echo "  0) Exit"
    echo "═══════════════════════════════════════════════════════════"
}

# Full test cycle
full_test_cycle() {
    log_step "Running full hot unplug/plug test cycle..."
    echo

    log_info "Step 1: Show initial state"
    show_pci_devices
    echo

    log_info "Step 2: Hot unplug device"
    hot_unplug
    echo

    log_info "Waiting 5 seconds..."
    sleep 5

    log_info "Step 3: Show state after unplug"
    show_pci_devices
    echo

    log_info "Step 4: Hot plug device back"
    hot_plug
    echo

    log_info "Waiting 5 seconds..."
    sleep 5

    log_info "Step 5: Show final state"
    show_pci_devices
    echo

    log_info "Full test cycle complete!"
}

# Check monitor connection first
check_monitor

# Interactive mode
if [ "$1" == "auto" ]; then
    # Automatic test mode
    full_test_cycle
else
    # Interactive menu
    while true; do
        show_menu
        read -p "Select option: " choice

        case $choice in
            1) show_pci_devices ;;
            2) show_qom_tree ;;
            3) hot_unplug ;;
            4) hot_plug ;;
            5) inject_pcie_error ;;
            6) inject_cxl_error ;;
            7) simulate_link_down ;;
            8) simulate_link_up ;;
            9) full_test_cycle ;;
            10) show_monitor_help ;;
            0) log_info "Exiting..."; exit 0 ;;
            *) log_error "Invalid option" ;;
        esac

        echo
        read -p "Press Enter to continue..."
    done
fi
