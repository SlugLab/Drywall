# CXL Type1 Coherency Testing and Kernel Structures Guide

## Overview

CXL Type1 devices provide cache-coherent memory access, which is critical for system correctness. This guide explains how to test coherency and documents the kernel structures involved.

## CXL Type1 Device Architecture

### What is CXL Type1?

CXL Type1 devices are **cache-coherent** memory expanders that appear as regular memory to the CPU. Unlike Type3 (non-coherent memory), Type1 devices participate in CPU cache coherency protocols.

Key characteristics:
- **Cache Coherent**: Maintains coherency with CPU caches via CXL.cache protocol
- **Memory Mapped**: Appears in system memory map
- **Low Latency**: Direct CPU access without I/O operations
- **Symmetric Access**: Both CPU and device can access coherently

## Kernel Data Structures

### Core CXL Structures

The Linux kernel maintains several key structures for CXL Type1 devices. Let me search for them:

