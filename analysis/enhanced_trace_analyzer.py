#!/usr/bin/env python3
"""
Enhanced RISC-V Trace Analyzer with Register State Tracking

This enhanced version tracks register state to calculate actual memory addresses
accessed by load/store instructions.
"""

import json
import os
import re
import sys
from collections import defaultdict
from dataclasses import dataclass
from enum import Enum
from typing import List, Dict, Set, Tuple, Optional, Any

@dataclass
class TraceEntry:
    """Represents a single trace entry"""
    timestamp: int
    pc: int
    instruction: int

@dataclass 
class MemoryAccess:
    """Represents a memory access with full details"""
    timestamp: int
    pc: int
    instruction: int
    instruction_type: str
    mnemonic: str
    address: int
    memory_region: Optional[str]
    register_used: int
    offset: int

class RegisterTracker:
    """Tracks register state throughout execution"""
    
    def __init__(self):
        # Initialize all 32 RISC-V registers to 0
        self.registers = [0] * 32
        # x0 is always 0
        self.registers[0] = 0
        
        # Track which registers have been explicitly set
        self.register_valid = [False] * 32
        self.register_valid[0] = True  # x0 is always valid (always 0)
    
    def set_register(self, reg_num: int, value: int):
        """Set register value"""
        if reg_num == 0:
            return  # x0 is hardwired to 0
        if 0 <= reg_num < 32:
            self.registers[reg_num] = value & 0xFFFFFFFF  # Keep 32-bit
            self.register_valid[reg_num] = True
    
    def get_register(self, reg_num: int) -> Optional[int]:
        """Get register value if valid"""
        if 0 <= reg_num < 32 and self.register_valid[reg_num]:
            return self.registers[reg_num]
        return None

class EnhancedRISCVAnalyzer:
    """Enhanced RISC-V analyzer with register tracking"""
    
    # RISC-V opcode constants
    OPCODE_MASK = 0x7F
    LOAD_OPCODE = 0x03
    STORE_OPCODE = 0x23
    IMMEDIATE_OPCODE = 0x13  # ADDI, SLTI, etc.
    REGISTER_OPCODE = 0x33   # ADD, SUB, etc.
    LUI_OPCODE = 0x37        # Load Upper Immediate
    AUIPC_OPCODE = 0x17      # Add Upper Immediate to PC
    
    def __init__(self):
        self.register_tracker = RegisterTracker()
    
    def is_riscv_instruction(self, instruction: int) -> bool:
        """Check if instruction is RISC-V (vs custom)"""
        opcode = instruction & self.OPCODE_MASK
        
        # Known RISC-V opcodes
        riscv_opcodes = {
            0x03, 0x23,  # Load/Store
            0x13, 0x33,  # Immediate/Register ops
            0x17, 0x37,  # AUIPC/LUI
            0x63, 0x67, 0x6F,  # Branch/Jump
        }
        
        return opcode in riscv_opcodes
    
    def execute_instruction(self, pc: int, instruction: int) -> Optional[MemoryAccess]:
        """Execute instruction and update register state, return memory access if any"""
        opcode = instruction & self.OPCODE_MASK
        
        if opcode == self.LOAD_OPCODE:
            return self._execute_load(pc, instruction)
        elif opcode == self.STORE_OPCODE:
            return self._execute_store(pc, instruction)
        elif opcode == self.IMMEDIATE_OPCODE:
            self._execute_immediate(instruction)
        elif opcode == self.REGISTER_OPCODE:
            self._execute_register(instruction)
        elif opcode == self.LUI_OPCODE:
            self._execute_lui(instruction)
        elif opcode == self.AUIPC_OPCODE:
            self._execute_auipc(pc, instruction)
        
        return None
    
    def _execute_load(self, pc: int, instruction: int) -> MemoryAccess:
        """Execute load instruction"""
        rd = (instruction >> 7) & 0x1F
        funct3 = (instruction >> 12) & 0x7
        rs1 = (instruction >> 15) & 0x1F
        imm = (instruction >> 20) & 0xFFF
        
        # Sign extend immediate
        if imm & 0x800:
            imm = imm | 0xFFFFF000
            imm = -(0x100000000 - imm)  # Convert to negative
        
        # Calculate address
        base_addr = self.register_tracker.get_register(rs1)
        if base_addr is None:
            base_addr = 0  # Assume 0 if register not tracked
        
        address = (base_addr + imm) & 0xFFFFFFFF
        
        # Load mnemonics
        load_mnemonics = {
            0b000: "LB", 0b001: "LH", 0b010: "LW",
            0b100: "LBU", 0b101: "LHU"
        }
        mnemonic = load_mnemonics.get(funct3, f"LOAD_{funct3}")
        
        # Update destination register (simplified - would need actual memory read)
        # For now, just mark register as having unknown value
        self.register_tracker.set_register(rd, 0)
        self.register_tracker.register_valid[rd] = False
        
        return MemoryAccess(
            timestamp=0, pc=pc, instruction=instruction,
            instruction_type="load", mnemonic=mnemonic,
            address=address, memory_region=None,
            register_used=rs1, offset=imm
        )
    
    def _execute_store(self, pc: int, instruction: int) -> MemoryAccess:
        """Execute store instruction"""
        imm_low = (instruction >> 7) & 0x1F
        funct3 = (instruction >> 12) & 0x7
        rs1 = (instruction >> 15) & 0x1F
        rs2 = (instruction >> 20) & 0x1F
        imm_high = (instruction >> 25) & 0x7F
        
        # Combine immediate
        imm = (imm_high << 5) | imm_low
        if imm & 0x800:
            imm = imm | 0xFFFFF000
            imm = -(0x100000000 - imm)
        
        # Calculate address
        base_addr = self.register_tracker.get_register(rs1)
        if base_addr is None:
            base_addr = 0
        
        address = (base_addr + imm) & 0xFFFFFFFF
        
        # Store mnemonics
        store_mnemonics = {0b000: "SB", 0b001: "SH", 0b010: "SW"}
        mnemonic = store_mnemonics.get(funct3, f"STORE_{funct3}")
        
        return MemoryAccess(
            timestamp=0, pc=pc, instruction=instruction,
            instruction_type="store", mnemonic=mnemonic,
            address=address, memory_region=None,
            register_used=rs1, offset=imm
        )
    
    def _execute_immediate(self, instruction: int):
        """Execute immediate arithmetic instruction"""
        rd = (instruction >> 7) & 0x1F
        funct3 = (instruction >> 12) & 0x7
        rs1 = (instruction >> 15) & 0x1F
        imm = (instruction >> 20) & 0xFFF
        
        # Sign extend immediate
        if imm & 0x800:
            imm = imm | 0xFFFFF000
            imm = -(0x100000000 - imm)
        
        rs1_val = self.register_tracker.get_register(rs1)
        if rs1_val is None:
            return
        
        if funct3 == 0b000:  # ADDI
            result = (rs1_val + imm) & 0xFFFFFFFF
            self.register_tracker.set_register(rd, result)
    
    def _execute_register(self, instruction: int):
        """Execute register-register instruction"""
        rd = (instruction >> 7) & 0x1F
        funct3 = (instruction >> 12) & 0x7
        rs1 = (instruction >> 15) & 0x1F
        rs2 = (instruction >> 20) & 0x1F
        funct7 = (instruction >> 25) & 0x7F
        
        rs1_val = self.register_tracker.get_register(rs1)
        rs2_val = self.register_tracker.get_register(rs2)
        
        if rs1_val is None or rs2_val is None:
            return
        
        if funct3 == 0b000 and funct7 == 0b0000000:  # ADD
            result = (rs1_val + rs2_val) & 0xFFFFFFFF
            self.register_tracker.set_register(rd, result)
    
    def _execute_lui(self, instruction: int):
        """Execute LUI (Load Upper Immediate)"""
        rd = (instruction >> 7) & 0x1F
        imm = instruction >> 12
        result = (imm << 12) & 0xFFFFFFFF
        self.register_tracker.set_register(rd, result)
    
    def _execute_auipc(self, pc: int, instruction: int):
        """Execute AUIPC (Add Upper Immediate to PC)"""
        rd = (instruction >> 7) & 0x1F
        imm = instruction >> 12
        result = (pc + (imm << 12)) & 0xFFFFFFFF
        self.register_tracker.set_register(rd, result)

class EnhancedTraceAnalyzer:
    """Enhanced trace analyzer with memory region mapping"""
    
    def __init__(self, memory_map_file: str):
        self.memory_regions = self._load_memory_map(memory_map_file)
        self.analyzer = EnhancedRISCVAnalyzer()
        
    def _load_memory_map(self, memory_map_file: str) -> List[Dict[str, Any]]:
        """Load memory map from JSON file"""
        try:
            with open(memory_map_file, 'r') as f:
                data = json.load(f)
            
            # Convert the trisc_map format to a list of regions
            regions = []
            trisc_map = data.get('trisc_map', {})
            
            for region_name, region_data in trisc_map.items():
                # Skip regions that don't have START/END addresses
                if 'START' not in region_data or 'END' not in region_data:
                    continue
                    
                region = {
                    'name': region_name,
                    'key': region_data.get('KEY', region_name),
                    'start_addr': region_data['START'],
                    'end_addr': region_data['END'],
                    'resides_within': region_data.get('RESIDES_WITHIN', []),
                    'num_bytes_per_register': region_data.get('NUM_BYTES_PER_REGISTER', 4)
                }
                regions.append(region)
            
            return regions
        except Exception as e:
            print(f"Error loading memory map: {e}")
            return []
    
    def _find_memory_region(self, address: int) -> Optional[str]:
        """Find the smallest memory region that contains the address"""
        # Find all regions that contain this address
        matching_regions = []
        
        for region in self.memory_regions:
            start_addr = int(region['start_addr'], 16) if isinstance(region['start_addr'], str) else region['start_addr']
            end_addr = int(region['end_addr'], 16) if isinstance(region['end_addr'], str) else region['end_addr']
            
            # Check if address falls within this region
            if start_addr <= address <= end_addr:
                matching_regions.append({
                    'name': region['name'],
                    'start': start_addr,
                    'end': end_addr,
                    'size': end_addr - start_addr + 1,
                    'resides_within': region['resides_within']
                })
        
        if not matching_regions:
            return None
        
        # Find the smallest region (most specific)
        # Sort by size (ascending) to get the smallest region first
        matching_regions.sort(key=lambda x: x['size'])
        
        # Return the name of the smallest region
        return matching_regions[0]['name']
    
    def analyze_trace(self, trace_file: str) -> List[MemoryAccess]:
        """Analyze trace file with register tracking"""
        memory_accesses = []
        
        try:
            with open(trace_file, 'r') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    
                    # Parse line
                    pattern = r'(\d+)\s+PC=([0-9a-fA-F]+),\s+instr=([0-9a-fA-F]+)'
                    match = re.match(pattern, line)
                    if not match:
                        continue
                    
                    timestamp = int(match.group(1))
                    pc = int(match.group(2), 16)
                    instruction = int(match.group(3), 16)
                    
                    # Only process RISC-V instructions
                    if not self.analyzer.is_riscv_instruction(instruction):
                        continue
                    
                    # Execute instruction and check for memory access
                    memory_access = self.analyzer.execute_instruction(pc, instruction)
                    if memory_access:
                        memory_access.timestamp = timestamp
                        memory_access.memory_region = self._find_memory_region(memory_access.address)
                        memory_accesses.append(memory_access)
                        
                        # Print progress for large files
                        # if len(memory_accesses) % 100 == 0:
                        #     print(f"Found {len(memory_accesses)} memory accesses...")
        
        except FileNotFoundError:
            print(f"Error: Trace file '{trace_file}' not found")
            sys.exit(1)
        
        return memory_accesses
    
    def generate_detailed_report(self, memory_accesses: List[MemoryAccess]) -> str:
        """Generate detailed analysis report"""
        report = []
        report.append("Enhanced RISC-V Memory Access Analysis")
        report.append("=" * 50)
        
        # Summary statistics
        total_accesses = len(memory_accesses)
        loads = [ma for ma in memory_accesses if ma.instruction_type == "load"]
        stores = [ma for ma in memory_accesses if ma.instruction_type == "store"]
        
        report.append(f"Total memory accesses: {total_accesses}")
        report.append(f"Load operations: {len(loads)}")
        report.append(f"Store operations: {len(stores)}")
        report.append("")
        
        # Memory region breakdown
        region_stats = defaultdict(int)
        for ma in memory_accesses:
            region = ma.memory_region or "Unknown"
            region_stats[region] += 1
        
        report.append("Memory Region Access Count:")
        for region, count in sorted(region_stats.items()):
            report.append(f"  {region}: {count}")
        report.append("")
        
        # Address range analysis
        if memory_accesses:
            addresses = [ma.address for ma in memory_accesses]
            min_addr = min(addresses)
            max_addr = max(addresses)
            report.append(f"Address range: 0x{min_addr:08x} - 0x{max_addr:08x}")
            report.append("")
        
        # Detailed listing
        report.append("Detailed Memory Access List:")
        report.append("-" * 40)
        
        for i, ma in enumerate(memory_accesses[:50]):  # Show first 50
            report.append(f"{i+1:3d}. Time: {ma.timestamp:>10} ns")
            report.append(f"     PC: 0x{ma.pc:08x}")
            report.append(f"     {ma.mnemonic} -> Address: 0x{ma.address:08x}")
            report.append(f"     Region: {ma.memory_region or 'Unknown'}")
            report.append(f"     Base reg: x{ma.register_used}, Offset: {ma.offset}")
            report.append("")
        
        if len(memory_accesses) > 50:
            report.append(f"... and {len(memory_accesses) - 50} more accesses")
        
        return "\n".join(report)

def analyze_trace_with_memory_map(trace_file: str, memory_map_dict: Dict[str, Any], output_prefix: Optional[str] = None) -> Tuple[List[MemoryAccess], str]:
    """
    Analyze trace files with a memory map provided as a dictionary.
    
    Args:
        trace_file: Path to the trace file to analyze
        memory_map_dict: Memory map as a dictionary (instead of loading from file)
        output_prefix: Optional prefix for output files. If None, uses trace_file base name
    
    Returns:
        Tuple of (memory_accesses list, report string)
    """
    # print("Enhanced RISC-V Trace Analysis Starting...")
    # print(f"Trace file: {trace_file}")
    # print("Memory map: provided as dictionary")
    # print("")
    
    # Create analyzer with memory map dict
    class DictBasedTraceAnalyzer(EnhancedTraceAnalyzer):
        def __init__(self, memory_map_dict: Dict[str, Any]):
            self.memory_regions = self._load_memory_map_from_dict(memory_map_dict)
            self.analyzer = EnhancedRISCVAnalyzer()
        
        def _load_memory_map_from_dict(self, memory_map_dict: Dict[str, Any]) -> List[Dict[str, Any]]:
            """Load memory map from dictionary"""
            try:
                # Convert the trisc_map format to a list of regions
                regions = []
                trisc_map = memory_map_dict.get('trisc_map', {})
                
                for region_name, region_data in trisc_map.items():
                    # Skip regions that don't have START/END addresses
                    if 'START' not in region_data or 'END' not in region_data:
                        continue
                        
                    region = {
                        'name': region_name,
                        'key': region_data.get('KEY', region_name),
                        'start_addr': region_data['START'],
                        'end_addr': region_data['END'],
                        'resides_within': region_data.get('RESIDES_WITHIN', []),
                        'num_bytes_per_register': region_data.get('NUM_BYTES_PER_REGISTER', 4)
                    }
                    regions.append(region)
                
                return regions
            except Exception as e:
                print(f"Error processing memory map dictionary: {e}")
                return []
    
    # Create analyzer
    analyzer = DictBasedTraceAnalyzer(memory_map_dict)
    
    # Analyze trace
    # print("Analyzing trace (this may take a while for large files)...")
    memory_accesses = analyzer.analyze_trace(trace_file)
    
    # print(f"Analysis complete! Found {len(memory_accesses)} memory accesses.")
    # print("")
    
    # Generate report
    report = analyzer.generate_detailed_report(memory_accesses)
    # print(report)
    # if "pcbuffer" in report:
    #     print(f"- trace file: {trace_file}")
    #     print(report)
    
    # Save detailed results to files
    base_name = output_prefix if output_prefix else trace_file.rsplit('.', 1)[0]
    
    # Save summary report
    report_file = f"{base_name}_memory_analysis.txt"
    with open(report_file, 'w') as f:
        f.write(report)
    
    # # Save CSV for further analysis
    csv_file = f"{base_name}_memory_accesses.csv"
    with open(csv_file, 'w') as f:
        f.write("timestamp,pc,instruction,type,mnemonic,address,region,base_reg,offset\n")
        for ma in memory_accesses:
            f.write(f"{ma.timestamp},0x{ma.pc:08x},0x{ma.instruction:08x},"
                   f"{ma.instruction_type},{ma.mnemonic},0x{ma.address:08x},"
                   f"{ma.memory_region or 'Unknown'},x{ma.register_used},{ma.offset}\n")
    
    # print(f"Reports saved to:")
    # print(f"  {report_file}")
    # print(f"  {csv_file}")
    
    return memory_accesses, report

def analyze_trace_file(trace_file: str, memory_map_file: str):
    """Analyze trace files and generate reports"""
    # Load memory map from file
    try:
        with open(memory_map_file, 'r') as f:
            memory_map_dict = json.load(f)
    except Exception as e:
        print(f"Error loading memory map file '{memory_map_file}': {e}")
        sys.exit(1)
    
    # Call the dictionary-based function
    return analyze_trace_with_memory_map(trace_file, memory_map_dict)

def analyze_trace_files(trace_files: list[str], memory_map_file: str):
    """Analyze trace files and generate reports"""
    # Load memory map from file
    try:
        with open(memory_map_file, 'r') as f:
            memory_map_dict = json.load(f)
    except Exception as e:
        print(f"Error loading memory map file '{memory_map_file}': {e}")
        sys.exit(1)
    
    # Call the dictionary-based function
    trace_files_memory_accesses: dict[str, tuple[list[MemoryAccess], str]] = dict()
    for trace_file in trace_files:
        trace_files_memory_accesses[trace_file] = analyze_trace_with_memory_map(trace_file, memory_map_dict)

    return trace_files_memory_accesses

def parse_neo_trisc_ids_from_trace_path(trace_file: str) -> tuple[int, int]:
    """
    Extract neoID and triscID from trace file path.
    
    Args:
        trace_file: Path to trace file
        
    Returns:
        Tuple of (neoID, triscID)
        
    Example:
        For path ending in ".t6[0].neo.u_t6.instrn_engine_wrapper.instrn_engine.trisc[0].gen.u_trisc..."
        Returns (0, 0)
    """
    import re
    
    # Extract neoID from pattern like ".t6[0].neo."
    neo_match = re.search(r'\.t6\[(\d+)\]\.neo\.', trace_file)
    neo_id = int(neo_match.group(1)) if neo_match else 0
    
    # Extract triscID from pattern like ".trisc[0].gen."
    trisc_match = re.search(r'\.trisc\[(\d+)\]\.gen\.', trace_file)
    trisc_id = int(trisc_match.group(1)) if trisc_match else 0
    
    return neo_id, trisc_id

def trace_files_to_memory_access_dict(trace_files: list[str], memory_map_dict: dict) -> dict[int, dict[int, list]]:
    """
    Convert trace files to organized memory access dictionary.
    
    Args:
        trace_files: List of trace file paths to analyze
        memory_map_dict: Pre-loaded memory map dictionary
        
    Returns:
        Dictionary organized as memory_accesses[neoID][triscID] = list of MemoryAccess objects
        
    Raises:
        ValueError: If the same neo/trisc combination appears in multiple files
    """
    memory_accesses_dict = {}
    
    for trace_file in trace_files:
        # Extract neo and trisc IDs
        neo_id, trisc_id = parse_neo_trisc_ids_from_trace_path(trace_file)
        
        # Check if this neo/trisc combination already exists
        if neo_id in memory_accesses_dict and trisc_id in memory_accesses_dict[neo_id]:
            raise ValueError(f"Duplicate neo/trisc combination found: neo_{neo_id}_trisc_{trisc_id} "
                           f"already exists. Current file: {trace_file}")
        
        # Initialize nested dictionary structure if needed
        if neo_id not in memory_accesses_dict:
            memory_accesses_dict[neo_id] = {}
        
        # Analyze trace file and get memory accesses
        memory_accesses, _ = analyze_trace_with_memory_map(trace_file, memory_map_dict)
        memory_accesses_dict[neo_id][trisc_id] = memory_accesses
        
        # print(f"Processed {trace_file}: neo_{neo_id}_trisc_{trisc_id} -> {len(memory_accesses)} memory accesses")
    
    return memory_accesses_dict

def find_smallest_memory_region(address: int, memory_map_dict: dict) -> Optional[str]:
    """
    Find the smallest memory region that contains the given address.
    
    Args:
        address: The memory address to lookup
        memory_map_dict: Memory map dictionary loaded from JSON
        
    Returns:
        Name of the smallest region containing the address, or None if not found
        
    The function handles nested regions by finding all regions that contain the address
    and returning the most specific one (the one with the smallest address range).
    """
    trisc_map = memory_map_dict.get('trisc_map', {})
    
    # Find all regions that contain this address
    matching_regions = []
    
    for region_name, region_data in trisc_map.items():
        # Skip regions that don't have START/END addresses
        if 'START' not in region_data or 'END' not in region_data:
            continue
            
        start_addr = int(region_data['START'], 16) if isinstance(region_data['START'], str) else region_data['START']
        end_addr = int(region_data['END'], 16) if isinstance(region_data['END'], str) else region_data['END']
        
        # Check if address falls within this region
        if start_addr <= address <= end_addr:
            matching_regions.append({
                'name': region_name,
                'start': start_addr,
                'end': end_addr,
                'size': end_addr - start_addr + 1,
                'resides_within': region_data.get('RESIDES_WITHIN', [])
            })
    
    if not matching_regions:
        return None
    
    # Find the smallest region (most specific)
    # Sort by size (ascending) to get the smallest region first
    matching_regions.sort(key=lambda x: x['size'])
    
    # Return the name of the smallest region
    return matching_regions[0]['name']

def get_memory_map_dict(memory_map_file: str) -> dict:
    """
    Load memory map dictionary from JSON file.
    
    Args:
        memory_map_file: Path to the JSON memory map file
        
    Returns:
        Dictionary containing the memory map data
        
    Raises:
        SystemExit: If the file cannot be loaded
    """
    try:
        with open(memory_map_file, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading memory map file '{memory_map_file}': {e}")
        sys.exit(1)

def detect_read_before_write_with_memory_map_dict(address: int, 
        trace_files: list[str], 
        memory_map_dict: dict, 
        mode: str = "combined") -> dict:
    """
    Detect if there is a read before write for a given address using pre-loaded memory map dictionary.
    
    Args:
        address: The memory address to check for read-before-write violations
        trace_files: List of trace file paths to analyze
        memory_map_dict: Pre-loaded memory map dictionary
        mode: Either "combined" (analyze all files together) or "separate" (analyze each file independently)
    
    Returns:
        Dictionary containing analysis results with the following structure:
        - If mode is "combined": {"violations": List[Dict], "first_access": Dict, "summary": Dict}
        - If mode is "separate": Dict[str, Dict] where keys are trace file names
    """
    if mode not in ["combined", "separate"]:
        raise ValueError("Mode must be 'combined' or 'separate'")
    
    def analyze_single_trace_for_address(trace_file: str) -> dict:
        """Analyze a single trace file for read-before-write violations"""
        memory_accesses, _ = analyze_trace_with_memory_map(trace_file, memory_map_dict)
        
        # Filter accesses for the specific address
        address_accesses = [ma for ma in memory_accesses if ma.address == address]
        
        if not address_accesses:
            return {
                "violations": [],
                "first_access": None,
                "summary": {
                    "total_accesses": 0,
                    "reads": 0,
                    "writes": 0,
                    "has_read_before_write": False
                }
            }
        
        # Sort by timestamp to get chronological order
        address_accesses.sort(key=lambda x: x.timestamp)
        
        violations = []
        reads = [ma for ma in address_accesses if ma.instruction_type == "load"]
        writes = [ma for ma in address_accesses if ma.instruction_type == "store"]
        
        # Check for read-before-write violations
        has_read_before_write = False
        first_write_time = None
        
        if writes:
            first_write_time = min(write.timestamp for write in writes)
        
        for read_access in reads:
            if first_write_time is None or read_access.timestamp < first_write_time:
                has_read_before_write = True
                violation = {
                    "type": "read_before_write",
                    "read_access": {
                        "timestamp": read_access.timestamp,
                        "pc": f"0x{read_access.pc:08x}",
                        "instruction": f"0x{read_access.instruction:08x}",
                        "mnemonic": read_access.mnemonic,
                        "register_used": f"x{read_access.register_used}",
                        "offset": read_access.offset
                    },
                    "first_write_time": first_write_time
                }
                violations.append(violation)
        
        return {
            "violations": violations,
            "first_access": {
                "timestamp": address_accesses[0].timestamp,
                "type": address_accesses[0].instruction_type,
                "pc": f"0x{address_accesses[0].pc:08x}",
                "mnemonic": address_accesses[0].mnemonic,
                "memory_region" : address_accesses[0].memory_region
            },
            "summary": {
                "total_accesses": len(address_accesses),
                "reads": len(reads),
                "writes": len(writes),
                "has_read_before_write": has_read_before_write,
                "address": f"0x{address:08x}"
            }
        }
    
    if mode == "separate":
        # Analyze each trace file independently
        results = {}
        for trace_file in trace_files:
            print(f"Analyzing {trace_file} for address 0x{address:08x}...")
            results[trace_file] = analyze_single_trace_for_address(trace_file)
        return results
    
    elif mode == "combined":
        # Analyze all trace files together
        print(f"Analyzing {len(trace_files)} trace files combined for address 0x{address:08x}...")
        
        all_accesses = []
        for trace_file in trace_files:
            memory_accesses, _ = analyze_trace_with_memory_map(trace_file, memory_map_dict)
            # Add source file information to each access
            for ma in memory_accesses:
                if ma.address == address:
                    # Create a copy with source file info
                    access_dict = {
                        'timestamp': ma.timestamp,
                        'pc': ma.pc,
                        'instruction': ma.instruction,
                        'instruction_type': ma.instruction_type,
                        'mnemonic': ma.mnemonic,
                        'address': ma.address,
                        'memory_region': ma.memory_region,
                        'register_used': ma.register_used,
                        'offset': ma.offset,
                        'source_file': trace_file
                    }
                    all_accesses.append(access_dict)
        
        if not all_accesses:
            return {
                "violations": [],
                "first_access": None,
                "summary": {
                    "total_accesses": 0,
                    "reads": 0,
                    "writes": 0,
                    "has_read_before_write": False,
                    "address": f"0x{address:08x}",
                    "trace_files": trace_files
                }
            }
        
        # Sort by timestamp to get chronological order across all files
        all_accesses.sort(key=lambda x: x['timestamp'])
        
        violations = []
        reads = [acc for acc in all_accesses if acc['instruction_type'] == "load"]
        writes = [acc for acc in all_accesses if acc['instruction_type'] == "store"]
        
        # Check for read-before-write violations
        has_read_before_write = False
        first_write_time = None
        
        if writes:
            first_write_time = min(write['timestamp'] for write in writes)
        
        for read_access in reads:
            if first_write_time is None or read_access['timestamp'] < first_write_time:
                has_read_before_write = True
                violation = {
                    "type": "read_before_write",
                    "read_access": {
                        "timestamp": read_access['timestamp'],
                        "pc": f"0x{read_access['pc']:08x}",
                        "instruction": f"0x{read_access['instruction']:08x}",
                        "mnemonic": read_access['mnemonic'],
                        "register_used": f"x{read_access['register_used']}",
                        "offset": read_access['offset'],
                        "source_file": read_access['source_file']
                    },
                    "first_write_time": first_write_time
                }
                violations.append(violation)
        
        return {
            "violations": violations,
            "first_access": {
                "timestamp": all_accesses[0]['timestamp'],
                "type": all_accesses[0]['instruction_type'],
                "pc": f"0x{all_accesses[0]['pc']:08x}",
                "mnemonic": all_accesses[0]['mnemonic'],
                "source_file": all_accesses[0]['source_file'],                
                "memory_region": all_accesses[0]['memory_region']
            },
            "summary": {
                "total_accesses": len(all_accesses),
                "reads": len(reads),
                "writes": len(writes),
                "has_read_before_write": has_read_before_write,
                "address": f"0x{address:08x}",
                "trace_files": trace_files
            }
        }

def detect_read_before_write_with_memory_access_dict(address: int, 
        memory_accesses_dict: dict[int, dict[int, list]], 
        mode: str = "combined") -> dict:
    """
    Detect if there is a read before write for a given address using pre-organized memory access dictionary.
    
    Args:
        address: The memory address to check for read-before-write violations
        memory_accesses_dict: Dictionary organized as [neoID][triscID] = list of MemoryAccess objects
        mode: Either "combined" (analyze all neo/trisc together) or "separate" (analyze each neo/trisc independently)
    
    Returns:
        Dictionary containing analysis results with the following structure:
        - If mode is "combined": {"violations": List[Dict], "first_access": Dict, "summary": Dict}
        - If mode is "separate": Dict[str, Dict] where keys are "neo_{neoID}_trisc_{triscID}"
    """
    if mode not in ["combined", "separate"]:
        raise ValueError("Mode must be 'combined' or 'separate'")
    
    def analyze_memory_accesses_for_address(memory_accesses: list, source_id: str = None) -> dict:
        """Analyze memory accesses for read-before-write violations"""
        # Filter accesses for the specific address
        address_accesses = [ma for ma in memory_accesses if ma.address == address]
        
        if not address_accesses:
            return {
                "violations": [],
                "first_access": None,
                "summary": {
                    "total_accesses": 0,
                    "reads": 0,
                    "writes": 0,
                    "has_read_before_write": False,
                    "address": f"0x{address:08x}"
                }
            }
        
        # Sort by timestamp to get chronological order
        address_accesses.sort(key=lambda x: x.timestamp)
        
        violations = []
        reads = [ma for ma in address_accesses if ma.instruction_type == "load"]
        writes = [ma for ma in address_accesses if ma.instruction_type == "store"]
        
        # Check for read-before-write violations
        has_read_before_write = False
        first_write_time = None
        
        if writes:
            first_write_time = min(write.timestamp for write in writes)
        
        for read_access in reads:
            if first_write_time is None or read_access.timestamp < first_write_time:
                has_read_before_write = True
                violation = {
                    "type": "read_before_write",
                    "read_access": {
                        "timestamp": read_access.timestamp,
                        "pc": f"0x{read_access.pc:08x}",
                        "instruction": f"0x{read_access.instruction:08x}",
                        "mnemonic": read_access.mnemonic,
                        "register_used": f"x{read_access.register_used}",
                        "offset": read_access.offset
                    },
                    "first_write_time": first_write_time
                }
                if source_id:
                    violation["read_access"]["source_id"] = source_id
                violations.append(violation)
        
        result = {
            "violations": violations,
            "first_access": {
                "timestamp": address_accesses[0].timestamp,
                "type": address_accesses[0].instruction_type,
                "pc": f"0x{address_accesses[0].pc:08x}",
                "mnemonic": address_accesses[0].mnemonic,
                "memory_region": address_accesses[0].memory_region
            },
            "summary": {
                "total_accesses": len(address_accesses),
                "reads": len(reads),
                "writes": len(writes),
                "has_read_before_write": has_read_before_write,
                "address": f"0x{address:08x}"
            }
        }
        
        if source_id:
            result["first_access"]["source_id"] = source_id
        
        return result
    
    if mode == "separate":
        # Analyze each neo/trisc combination separately
        results = {}
        for neo_id, trisc_dict in memory_accesses_dict.items():
            for trisc_id, memory_accesses in trisc_dict.items():
                source_id = f"neo_{neo_id}_trisc_{trisc_id}"
                results[source_id] = analyze_memory_accesses_for_address(memory_accesses, source_id)
        return results
    
    elif mode == "combined":
        # Combine all memory accesses across all neo/trisc combinations
        all_accesses = []
        for neo_id, trisc_dict in memory_accesses_dict.items():
            for trisc_id, memory_accesses in trisc_dict.items():
                # Add source information to each access
                for ma in memory_accesses:
                    if ma.address == address:
                        # Create a copy with source file info
                        access_dict = {
                            'timestamp': ma.timestamp,
                            'pc': ma.pc,
                            'instruction': ma.instruction,
                            'instruction_type': ma.instruction_type,
                            'mnemonic': ma.mnemonic,
                            'address': ma.address,
                            'memory_region': ma.memory_region,
                            'register_used': ma.register_used,
                            'offset': ma.offset,
                            'source_id': f"neo_{neo_id}_trisc_{trisc_id}"
                        }
                        all_accesses.append(access_dict)
        
        if not all_accesses:
            return {
                "violations": [],
                "first_access": None,
                "summary": {
                    "total_accesses": 0,
                    "reads": 0,
                    "writes": 0,
                    "has_read_before_write": False,
                    "address": f"0x{address:08x}",
                    "neo_trisc_combinations": list(f"neo_{neo_id}_trisc_{trisc_id}" 
                                                  for neo_id in memory_accesses_dict.keys() 
                                                  for trisc_id in memory_accesses_dict[neo_id].keys())
                }
            }
        
        # Sort by timestamp to get chronological order across all neo/trisc
        all_accesses.sort(key=lambda x: x['timestamp'])
        
        violations = []
        reads = [acc for acc in all_accesses if acc['instruction_type'] == "load"]
        writes = [acc for acc in all_accesses if acc['instruction_type'] == "store"]
        
        # Check for read-before-write violations
        has_read_before_write = False
        first_write_time = None
        
        if writes:
            first_write_time = min(write['timestamp'] for write in writes)
        
        for read_access in reads:
            if first_write_time is None or read_access['timestamp'] < first_write_time:
                has_read_before_write = True
                violation = {
                    "type": "read_before_write",
                    "read_access": {
                        "timestamp": read_access['timestamp'],
                        "pc": f"0x{read_access['pc']:08x}",
                        "instruction": f"0x{read_access['instruction']:08x}",
                        "mnemonic": read_access['mnemonic'],
                        "register_used": f"x{read_access['register_used']}",
                        "offset": read_access['offset'],
                        "source_id": read_access['source_id']
                    },
                    "first_write_time": first_write_time
                }
                violations.append(violation)
        
        return {
            "violations": violations,
            "first_access": {
                "timestamp": all_accesses[0]['timestamp'],
                "type": all_accesses[0]['instruction_type'],
                "pc": f"0x{all_accesses[0]['pc']:08x}",
                "mnemonic": all_accesses[0]['mnemonic'],
                "source_id": all_accesses[0]['source_id'],
                "memory_region": all_accesses[0]['memory_region']
            },
            "summary": {
                "total_accesses": len(all_accesses),
                "reads": len(reads),
                "writes": len(writes),
                "has_read_before_write": has_read_before_write,
                "address": f"0x{address:08x}",
                "neo_trisc_combinations": list(f"neo_{neo_id}_trisc_{trisc_id}" 
                                              for neo_id in memory_accesses_dict.keys() 
                                              for trisc_id in memory_accesses_dict[neo_id].keys())
            }
        }

def detect_read_before_write(address: int, 
        trace_files: list[str], 
        memory_map_file: str, 
        mode: str = "combined") -> dict:
    """
    Detect if there is a read before write for a given address.
    
    Args:
        address: The memory address to check for read-before-write violations
        trace_files: List of trace file paths to analyze
        memory_map_file: Path to the JSON memory map file
        mode: Either "combined" (analyze all files together) or "separate" (analyze each file independently)
    
    Returns:
        Dictionary containing analysis results with the following structure:
        - If mode is "combined": {"violations": List[Dict], "first_access": Dict, "summary": Dict}
        - If mode is "separate": Dict[str, Dict] where keys are trace file names
    """
    if mode not in ["combined", "separate"]:
        raise ValueError("Mode must be 'combined' or 'separate'")
    
    # Load memory map
    try:
        with open(memory_map_file, 'r') as f:
            memory_map_dict = json.load(f)
    except Exception as e:
        print(f"Error loading memory map file '{memory_map_file}': {e}")
        return {}
    
    # Call the function with pre-loaded memory map dictionary
    return detect_read_before_write_with_memory_map_dict(address, trace_files, memory_map_dict, mode)

def detect_all_read_before_write(trace_files: list[str], memory_map_file: str, mode: str = "combined") -> dict:
    """
    Detect read-before-write violations for all accessed addresses across trace files.
    
    Args:
        trace_files: List of trace file paths to analyze
        memory_map_file: Path to the JSON memory map file
        mode: Either "combined" (analyze all files together) or "separate" (analyze each file independently)
    
    Returns:
        Dictionary containing analysis results:
        - If mode is "combined": {"address_results": Dict[str, Dict], "summary": Dict}
        - If mode is "separate": Dict[str, Dict[str, Dict]] where first keys are neo_trisc combinations, second keys are addresses
    """
    if mode not in ["combined", "separate"]:
        raise ValueError("Mode must be 'combined' or 'separate'")
    
    # Load memory map
    memory_map_dict = get_memory_map_dict(memory_map_file)
    
    # Create memory access dictionary from trace files (reads files only once)
    # print(f"Processing {len(trace_files)} trace files...")
    memory_accesses_dict = trace_files_to_memory_access_dict(trace_files, memory_map_dict)
    
    # Get all unique addresses across all neo/trisc combinations
    all_addresses = set()
    for neo_id, trisc_dict in memory_accesses_dict.items():
        for trisc_id, memory_accesses in trisc_dict.items():
            for ma in memory_accesses:
                all_addresses.add(ma.address)
    
    # print(f"Found {len(all_addresses)} unique addresses across all trace files")
    
    if mode == "separate":
        # Analyze each neo/trisc combination separately
        results = {}
        for neo_id, trisc_dict in memory_accesses_dict.items():
            for trisc_id, memory_accesses in trisc_dict.items():
                source_id = f"neo_{neo_id}_trisc_{trisc_id}"
                print(f"Analyzing {source_id} for all addresses...")
                
                # Get unique addresses for this neo/trisc combination
                unique_addresses = set(ma.address for ma in memory_accesses)
                print(f"  Found {len(unique_addresses)} unique addresses in {source_id}")
                
                # Create single-entry dict for this neo/trisc combination
                single_memory_dict = {neo_id: {trisc_id: memory_accesses}}
                
                source_results = {}
                for address in sorted(unique_addresses):
                    result = detect_read_before_write_with_memory_access_dict(
                        address, single_memory_dict, "separate"
                    )
                    # Extract the result for this specific source_id
                    if source_id in result:
                        source_results[f"0x{address:08x}"] = result[source_id]
                
                results[source_id] = source_results
        
        return results
    
    elif mode == "combined":
        # Analyze all addresses using the combined memory access dictionary
        # print(f"Analyzing all addresses in combined mode...")
        
        address_results = {}
        total_violations = 0
        addresses_with_violations = 0
        
        for address in sorted(all_addresses):
            # print(f"  Checking address 0x{address:08x}...")
            result = detect_read_before_write_with_memory_access_dict(
                address, memory_accesses_dict, "combined"
            )
            address_key = f"0x{address:08x}"
            address_results[address_key] = result
            
            if result["summary"]["has_read_before_write"]:
                addresses_with_violations += 1
                total_violations += len(result["violations"])
        
        # Create overall summary
        summary = {
            "total_addresses": len(all_addresses),
            "addresses_with_violations": addresses_with_violations,
            "total_violations": total_violations,
            "violation_rate": addresses_with_violations / len(all_addresses) if all_addresses else 0,
            "trace_files": trace_files,
            "neo_trisc_combinations": list(f"neo_{neo_id}_trisc_{trisc_id}" 
                                          for neo_id in memory_accesses_dict.keys() 
                                          for trisc_id in memory_accesses_dict[neo_id].keys())
        }
        
        return {
            "address_results": address_results,
            "summary": summary
        }

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Enhanced RISC-V Trace Analyzer with Register State Tracking",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python enhanced_trace_analyzer.py trace.txt memory_map.json
  python enhanced_trace_analyzer.py --trace-file trace.txt --memory-map memory_map.json
        """
    )
    
    parser.add_argument(
        'trace_file', 
        help='Path to the trace file to analyze'
    )
    
    parser.add_argument(
        'memory_map_file',
        help='Path to the JSON memory map file'
    )
    
    args = parser.parse_args()
    
    analyze_trace_file(args.trace_file, args.memory_map_file)