#!/usr/bin/env python3
import sys
import subprocess
import re
import os
from pathlib import Path
from typing import Dict, List, Tuple
from dataclasses import dataclass
from enum import Enum

class Feature(Enum):
    ENABLED = "Enabled"
    DISABLED = "Disabled"
    PARTIAL = "Partial"
    UNKNOWN = "Unknown"

@dataclass
class SecurityFeatures:
    aslr: Feature = Feature.UNKNOWN
    nx: Feature = Feature.UNKNOWN
    pie: Feature = Feature.UNKNOWN
    relro: Feature = Feature.UNKNOWN
    stack_protection: Feature = Feature.UNKNOWN

@dataclass
class SanitizerFeatures:
    asan: Feature = Feature.UNKNOWN
    tsan: Feature = Feature.UNKNOWN
    msan: Feature = Feature.UNKNOWN
    ubsan: Feature = Feature.UNKNOWN

@dataclass
class CoverageFeatures:
    # Coverage granularity
    func: Feature = Feature.UNKNOWN
    bb: Feature = Feature.UNKNOWN    # Basic Block
    edge: Feature = Feature.UNKNOWN
    # Tracing type
    trace: Feature = Feature.UNKNOWN
    trace_type: str = "None"  # Will store "trace-pc", "trace-pc-guard", or "None"

class BinaryAnalyzer:
    def __init__(self, binary_path: str):
        self.binary_path = binary_path
        self.security = SecurityFeatures()
        self.sanitizer = SanitizerFeatures()
        self.coverage = CoverageFeatures()
        
    def _run_command(self, cmd: List[str], encoding='utf-8') -> Tuple[str, int]:
        """Run command and return output and return code."""
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, encoding=encoding)
            return result.stdout + result.stderr, result.returncode
        except subprocess.CalledProcessError as e:
            return e.output if e.output else "", e.returncode
        except FileNotFoundError:
            return f"Command not found: {cmd[0]}", -1

    def check_security_features(self):
        # Check ASLR
        self._check_aslr()
        
        # Check NX
        self._check_nx()
        
        # Check PIE
        self._check_pie()
        
        # Check RELRO
        self._check_relro()
        
        # Check Stack Protection
        self._check_stack_protection()

    def _check_aslr(self):
        output, _ = self._run_command(['readelf', '-d', self.binary_path])
        if 'BIND_NOW' in output:
            self.security.aslr = Feature.ENABLED
        else:
            self.security.aslr = Feature.DISABLED

    def _check_nx(self):
        """
        Check for NX (No-eXecute) protection.
        NX is enabled if:
        1. GNU_STACK segment exists
        2. It doesn't have the executable flag (E) set
        3. Stack is marked RW (read-write) but not E (executable)
        """
        output, _ = self._run_command(['readelf', '-W', '-l', self.binary_path])
        
        # Look for GNU_STACK segment and its permissions
        stack_rx = re.search(r'GNU_STACK\s+(?:[0-9a-fA-F]+\s+){5}([RWE]+)', output)
        
        if stack_rx:
            # If we find GNU_STACK, check if it's non-executable (no 'E' flag)
            permissions = stack_rx.group(1)
            self.security.nx = Feature.ENABLED if 'E' not in permissions else Feature.DISABLED
        else:
            # If we can't find GNU_STACK, check for any executable stack indicators
            if 'Stack executable' in output or 'GNU_STACK.*RWE' in output:
                self.security.nx = Feature.DISABLED
            else:
                # Modern systems default to NX if not explicitly marked executable
                self.security.nx = Feature.ENABLED

    def _check_pie(self):
        """
        Check for Position Independent Executable (PIE) using file command.
        The file command is very reliable at detecting PIE/no-PIE binaries.
        """
        file_output, ret = self._run_command(['file', self.binary_path])
        
        # file command output contains 'pie' for PIE executables
        if 'pie' in file_output.lower():
            self.security.pie = Feature.ENABLED
        else:
            self.security.pie = Feature.DISABLED

    def _check_relro(self):
        """
        Check for RELRO (RELocation Read-Only) protection.
        - Full RELRO: Both 'BIND_NOW' and 'RELRO' flags are present
        - Partial RELRO: Only 'RELRO' flag is present
        - No RELRO: Neither flag is present
        """
        output, _ = self._run_command(['readelf', '-l', self.binary_path])
        has_relro = 'GNU_RELRO' in output
        
        output_dynamic, _ = self._run_command(['readelf', '-d', self.binary_path])
        has_bindnow = 'BIND_NOW' in output_dynamic
        
        if has_relro and has_bindnow:
            self.security.relro = Feature.ENABLED  # Full RELRO
        elif has_relro:
            self.security.relro = Feature.PARTIAL  # Partial RELRO
        else:
            self.security.relro = Feature.DISABLED  # No RELRO

    def _check_stack_protection(self):
        """
        Check for stack protection (stack canary).
        Looks for symbols that indicate stack protector is present.
        """
        output, _ = self._run_command(['readelf', '-s', self.binary_path])
        if '__stack_chk_fail' in output or '__stack_chk_guard' in output:
            self.security.stack_protection = Feature.ENABLED
        else:
            self.security.stack_protection = Feature.DISABLED

    def check_sanitizer_features(self):
        """
        Check symbols and sections for various sanitizers.
        Each sanitizer has its own specific symbols to look for.
        """
        symbols_output, _ = self._run_command(['nm', '-a', self.binary_path])
        
        # ASan - Address Sanitizer specific symbols
        asan_symbols = [
            '__asan_init',
            '__asan_version_mismatch',
            '__asan_report_load',
            '__asan_report_store'
        ]
        if any(sym in symbols_output for sym in asan_symbols):
            self.sanitizer.asan = Feature.ENABLED
        else:
            self.sanitizer.asan = Feature.DISABLED

        # TSan - Thread Sanitizer specific symbols
        tsan_symbols = [
            '__tsan_init',
            '__tsan_report',
            '__tsan_mutex',
            '__tsan_read',
            '__tsan_write'
        ]
        if any(sym in symbols_output for sym in tsan_symbols):
            self.sanitizer.tsan = Feature.ENABLED
        else:
            self.sanitizer.tsan = Feature.DISABLED

        # MSan - Memory Sanitizer specific symbols
        msan_symbols = [
            '__msan_init',
            '__msan_warning',
            '__msan_track_origins',
            '__msan_allocated_memory'
        ]
        if any(sym in symbols_output for sym in msan_symbols):
            self.sanitizer.msan = Feature.ENABLED
        else:
            self.sanitizer.msan = Feature.DISABLED

        # UBSan - Undefined Behavior Sanitizer specific symbols
        ubsan_symbols = [
            '_GLOBAL__sub_I_ubsan_init_standalone.cpp',
            '_ZN7__ubsan23InitializeDeadlySignalsEv',
            '_ZN7__ubsanL13OnStackUnwindERKN11__sanitizer13SignalContextEPKvPNS0_18BufferedStackTraceE',
            '_ZN7__ubsanL14is_initializedE',
            '_ZN7__ubsanL19PreInitAsStandaloneEv',
            '_ZN7__ubsanL19UBsanOnDeadlySignalEiPvS0_',
            'ubsan_init_standalone.cpp.o',
            'ubsan_init_standalone_preinit.cpp.o',
            'ubsan_signals_standalone.cpp.o'
        ]
        if any(sym in symbols_output for sym in ubsan_symbols):
            self.sanitizer.ubsan = Feature.ENABLED
        else:
            self.sanitizer.ubsan = Feature.DISABLED

    def _check_trace_pc(self, symbols_output: str) -> Feature:
        """
        Check for trace-pc coverage instrumentation.
        This is the simple PC tracing without guards.
        """
        trace_pc_symbols = [
            '__sanitizer_cov_trace_pc',
            '__sancov_trace_pc'
        ]
        return Feature.ENABLED if any(sym in symbols_output for sym in trace_pc_symbols) else Feature.DISABLED

    def _check_trace_pc_guard(self, symbols_output: str) -> Feature:
        """
        Check for trace-pc-guard coverage instrumentation.
        This is the more efficient PC tracing with guard variables.
        Look for both initialization and trace symbols.
        """
        guard_symbols = [
            '__sanitizer_cov_trace_pc_guard',
            '__sanitizer_cov_trace_pc_guard_init',
            '__sancov_guard'
        ]
        # Need both the guard function and its initialization
        has_guard = '__sanitizer_cov_trace_pc_guard' in symbols_output
        has_init = '__sanitizer_cov_trace_pc_guard_init' in symbols_output
        
        return Feature.ENABLED if (has_guard and has_init) else Feature.DISABLED

    def check_coverage_features(self):
        """
        Check for sanitizer coverage instrumentation features.
        - Granularity checks: func, bb (basic block), edge
        - Tracing check: presence of either trace-pc or trace-pc-guard
        """
        symbols_output, _ = self._run_command(['nm', '-a', self.binary_path])
        
        # Function-level coverage
        if '__sanitizer_cov_function' in symbols_output or '__sanitizer_cov_with_check' in symbols_output:
            self.coverage.func = Feature.ENABLED
        else:
            self.coverage.func = Feature.DISABLED

        # Basic block coverage
        if '__sanitizer_cov_trace_basic_block' in symbols_output:
            self.coverage.bb = Feature.ENABLED
        else:
            self.coverage.bb = Feature.DISABLED

        # Edge coverage
        if '__sanitizer_cov_trace_edge' in symbols_output:
            self.coverage.edge = Feature.ENABLED
        else:
            self.coverage.edge = Feature.DISABLED

        # Check for trace-pc-guard instrumentation
        guard_symbols = [
            '__sanitizer_cov_trace_pc_guard',
            '__sanitizer_cov_trace_pc_guard_init',
            '__sanitizer_dump_trace_pc_guard_coverage',
            'sancov.module_ctor_trace_pc_guard',
            '_sancov_guards',
            'pc_guard_controller'
        ]
        
        # Count how many of the required symbols are present
        guard_symbols_found = sum(1 for sym in guard_symbols if sym in symbols_output)
        all_guard_symbols = len(guard_symbols)
        
        if guard_symbols_found == all_guard_symbols:
            self.coverage.trace = Feature.ENABLED
            self.coverage.trace_type = "trace-pc-guard"
        elif guard_symbols_found == 5:  # Exactly 5 symbols
            self.coverage.trace = Feature.ENABLED
            self.coverage.trace_type = "partial trace-pc-guard"
        elif guard_symbols_found >= 1:  # Between 1 and 4 symbols
            self.coverage.trace = Feature.ENABLED
            self.coverage.trace_type = f"trace-pc-guard ({guard_symbols_found}/{all_guard_symbols} symbols) - likely only trace-pc"
        elif '__sanitizer_cov_trace_pc' in symbols_output:
            self.coverage.trace = Feature.ENABLED
            self.coverage.trace_type = "trace-pc"
        else:
            self.coverage.trace = Feature.DISABLED
            self.coverage.trace_type = "None"

    def analyze(self) -> bool:
        """Perform full analysis of the binary."""
        if not Path(self.binary_path).exists():
            print(f"Error: Binary '{self.binary_path}' not found")
            return False

        try:
            self.check_security_features()
            self.check_sanitizer_features()
            self.check_coverage_features()
            return True
        except Exception as e:
            print(f"Error during analysis: {str(e)}")
            return False

    def print_report(self):
        """Print formatted analysis report."""
        print(f"\nSecurity Features Analysis for: {self.binary_path}")
        print("-" * 40)
        print(f"ASLR:               {self.security.aslr.value:>10}")
        print(f"NX/DEP:            {self.security.nx.value:>10}")
        print(f"PIE:               {self.security.pie.value:>10}")
        print(f"RELRO:             {self.security.relro.value:>10}")
        print(f"Stack Protection:   {self.security.stack_protection.value:>10}")

        print("\nSanitizer Features:")
        print("-" * 40)
        print(f"AddressSanitizer:  {self.sanitizer.asan.value:>10}")
        print(f"ThreadSanitizer:   {self.sanitizer.tsan.value:>10}")
        print(f"MemorySanitizer:   {self.sanitizer.msan.value:>10}")
        print(f"UBSan:             {self.sanitizer.ubsan.value:>10}")

        print("\nCoverage Features:")
        print("-" * 40)
        print(f"Function:          {self.coverage.func.value:>10}")
        print(f"Basic Block:       {self.coverage.bb.value:>10}")
        print(f"Edge:              {self.coverage.edge.value:>10}")
        print(f"Trace:             {self.coverage.trace.value:>10}  ({self.coverage.trace_type})")

def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <binary_path>")
        sys.exit(1)

    binary_path = sys.argv[1]
    analyzer = BinaryAnalyzer(binary_path)
    
    if analyzer.analyze():
        analyzer.print_report()
        sys.exit(0)
    else:
        sys.exit(1)

if __name__ == "__main__":
    main()
