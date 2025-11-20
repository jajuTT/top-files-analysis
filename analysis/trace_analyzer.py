#!/usr/bin/env python3
"""
RISC-V Trace Analyzer

This script analyzes a RISC-V instruction trace file and identifies instructions
that access memory regions defined in a memory map file.

Usage:
    python trace_analyzer.py <trace_file> <memory_map_file>
"""

import json
import re
import sys
from typing import List, Dict, Set, Tuple, Optional
from dataclasses import dataclass
from enum import Enum

@dataclass
class TraceEntry:
    """Represents a single trace entry"""
    timestamp: int
    pc: int
    instruction: int
    
@dataclass
class MemoryRegion:
    """Represents a memory region from memory map"""
    name: str
    start_addr: int
    end_addr: int
    size: int

class InstructionType(Enum):
    """RISC-V instruction types"""
    LOAD = "load"
    STORE = "store"
    OTHER = "other"

class RISCVInstructionAnalyzer:
    """Analyzes RISC-V instructions for memory access patterns"""
    
    # RISC-V opcode masks and patterns
    OPCODE_MASK = 0x7F
    
    # Load instructions (opcode = 0000011)
    LOAD_OPCODE = 0x03
    
    # Store instructions (opcode = 0100011)  
    STORE_OPCODE = 0x23
    
    # Load instruction function codes
    LOAD_FUNCTIONS = {
        0b000: "LB",    # Load byte
        0b001: "LH",    # Load halfword
        0b010: "LW",    # Load word
        0b100: "LBU",   # Load byte unsigned
        0b101: "LHU",   # Load halfword unsigned
    }
    
    # Store instruction function codes
    STORE_FUNCTIONS = {
        0b000: "SB",    # Store byte
        0b001: "SH",    # Store halfword
        0b010: "SW",    # Store word
    }
    
    def __init__(self):
        pass
    
    def is_riscv_instruction(self, instruction: int) -> bool:
        """
        Determine if an instruction is a RISC-V instruction vs custom instruction.
        This is a placeholder - you'll need to implement the actual logic
        based on your custom instruction encoding.
        """
        # Placeholder: assume RISC-V if it follows basic RISC-V encoding patterns
        opcode = instruction & self.OPCODE_MASK
        
        # Check if it's a known RISC-V opcode
        known_opcodes = {
            0x03, 0x23,  # Load/Store
            0x13, 0x33,  # Immediate/Register arithmetic
            0x17, 0x37,  # AUIPC/LUI
            0x63, 0x67, 0x6F,  # Branch/Jump
        }
        
        return opcode in known_opcodes
    
    def get_instruction_type(self, instruction: int) -> InstructionType:
        """Determine if instruction is load, store, or other"""
        opcode = instruction & self.OPCODE_MASK
        
        if opcode == self.LOAD_OPCODE:
            return InstructionType.LOAD
        elif opcode == self.STORE_OPCODE:
            return InstructionType.STORE
        else:
            return InstructionType.OTHER
    
    def decode_load_instruction(self, instruction: int) -> Dict:
        """Decode a load instruction"""
        opcode = instruction & 0x7F
        rd = (instruction >> 7) & 0x1F
        funct3 = (instruction >> 12) & 0x7
        rs1 = (instruction >> 15) & 0x1F
        imm = (instruction >> 20) & 0xFFF
        
        # Sign extend immediate
        if imm & 0x800:
            imm |= 0xFFFFF000
        
        mnemonic = self.LOAD_FUNCTIONS.get(funct3, f"UNKNOWN_LOAD_{funct3}")
        
        return {
            'type': 'load',
            'mnemonic': mnemonic,
            'rd': rd,
            'rs1': rs1,
            'immediate': imm,
            'uses_memory': True
        }
    
    def decode_store_instruction(self, instruction: int) -> Dict:
        """Decode a store instruction"""
        opcode = instruction & 0x7F
        imm_low = (instruction >> 7) & 0x1F
        funct3 = (instruction >> 12) & 0x7
        rs1 = (instruction >> 15) & 0x1F
        rs2 = (instruction >> 20) & 0x1F
        imm_high = (instruction >> 25) & 0x7F
        
        # Combine immediate fields
        imm = (imm_high << 5) | imm_low
        
        # Sign extend immediate
        if imm & 0x800:
            imm |= 0xFFFFF000
        
        mnemonic = self.STORE_FUNCTIONS.get(funct3, f"UNKNOWN_STORE_{funct3}")
        
        return {
            'type': 'store',
            'mnemonic': mnemonic,
            'rs1': rs1,
            'rs2': rs2,
            'immediate': imm,
            'uses_memory': True
        }
    
    def decode_instruction(self, instruction: int) -> Dict:
        """Decode a RISC-V instruction"""
        inst_type = self.get_instruction_type(instruction)
        
        if inst_type == InstructionType.LOAD:
            return self.decode_load_instruction(instruction)
        elif inst_type == InstructionType.STORE:
            return self.decode_store_instruction(instruction)
        else:
            return {
                'type': 'other',
                'uses_memory': False
            }

class MemoryMapLoader:
    """Loads and manages memory map from JSON file"""
    
    def __init__(self, memory_map_file: str):
        self.memory_regions = self.load_memory_map(memory_map_file)
    
    def load_memory_map(self, memory_map_file: str) -> List[MemoryRegion]:
        """Load memory map from JSON file"""
        try:
            with open(memory_map_file, 'r') as f:
                memory_map_data = json.load(f)
            
            regions = []
            for region_data in memory_map_data.get('regions', []):
                region = MemoryRegion(
                    name=region_data['name'],
                    start_addr=int(region_data['start_addr'], 16) if isinstance(region_data['start_addr'], str) else region_data['start_addr'],
                    end_addr=int(region_data['end_addr'], 16) if isinstance(region_data['end_addr'], str) else region_data['end_addr'],
                    size=region_data.get('size', 0)
                )
                regions.append(region)
            
            return regions
            
        except FileNotFoundError:
            print(f"Error: Memory map file '{memory_map_file}' not found")
            sys.exit(1)
        except json.JSONDecodeError as e:
            print(f"Error: Invalid JSON in memory map file: {e}")
            sys.exit(1)
        except KeyError as e:
            print(f"Error: Missing required field in memory map: {e}")
            sys.exit(1)
    
    def find_memory_region(self, address: int) -> Optional[MemoryRegion]:
        """Find which memory region contains the given address"""
        for region in self.memory_regions:
            if region.start_addr <= address <= region.end_addr:
                return region
        return None

class TraceAnalyzer:
    """Main trace analyzer class"""
    
    def __init__(self, memory_map_file: str):
        self.memory_map = MemoryMapLoader(memory_map_file)
        self.riscv_analyzer = RISCVInstructionAnalyzer()
        self.memory_accessing_instructions = []
    
    def parse_trace_line(self, line: str) -> Optional[TraceEntry]:
        """Parse a single line from the trace file"""
        line = line.strip()
        if not line:
            return None
        
        # Parse format: timestamp PC=address, instr=instruction
        pattern = r'(\d+)\s+PC=([0-9a-fA-F]+),\s+instr=([0-9a-fA-F]+)'
        match = re.match(pattern, line)
        
        if not match:
            return None
        
        timestamp = int(match.group(1))
        pc = int(match.group(2), 16)
        instruction = int(match.group(3), 16)
        
        return TraceEntry(timestamp, pc, instruction)
    
    def calculate_memory_address(self, decoded_inst: Dict, registers: Dict[int, int] = None) -> Optional[int]:
        """
        Calculate the memory address accessed by a load/store instruction.
        Note: This requires register state which isn't available in the trace.
        This is a placeholder for demonstration.
        """
        # In a real implementation, you'd need to track register state
        # throughout execution to calculate effective addresses
        
        if registers is None:
            # Without register tracking, we can't calculate the actual address
            return None
        
        if decoded_inst['type'] in ['load', 'store']:
            base_addr = registers.get(decoded_inst['rs1'], 0)
            offset = decoded_inst['immediate']
            return base_addr + offset
        
        return None
    
    def analyze_trace_file(self, trace_file: str) -> List[Dict]:
        """Analyze the entire trace file"""
        memory_accessing_instructions = []
        
        try:
            with open(trace_file, 'r') as f:
                for line_num, line in enumerate(f, 1):
                    entry = self.parse_trace_line(line)
                    if not entry:
                        continue
                    
                    # Check if it's a RISC-V instruction
                    if not self.riscv_analyzer.is_riscv_instruction(entry.instruction):
                        continue
                    
                    # Decode the instruction
                    decoded = self.riscv_analyzer.decode_instruction(entry.instruction)
                    
                    # Check if it accesses memory
                    if decoded.get('uses_memory', False):
                        # Note: Without register state tracking, we can't determine
                        # the exact memory address being accessed. In a full implementation,
                        # you would need to track register values throughout execution.
                        
                        result = {
                            'line_number': line_num,
                            'timestamp': entry.timestamp,
                            'pc': hex(entry.pc),
                            'instruction': hex(entry.instruction),
                            'decoded': decoded,
                            'memory_address': None,  # Would need register tracking
                            'memory_region': None
                        }
                        
                        memory_accessing_instructions.append(result)
        
        except FileNotFoundError:
            print(f"Error: Trace file '{trace_file}' not found")
            sys.exit(1)
        
        return memory_accessing_instructions
    
    def generate_report(self, memory_accessing_instructions: List[Dict]) -> str:
        """Generate a formatted report"""
        report = []
        report.append("RISC-V Memory Access Analysis Report")
        report.append("=" * 50)
        report.append(f"Total memory-accessing instructions found: {len(memory_accessing_instructions)}")
        report.append("")
        
        # Group by instruction type
        loads = [inst for inst in memory_accessing_instructions if inst['decoded']['type'] == 'load']
        stores = [inst for inst in memory_accessing_instructions if inst['decoded']['type'] == 'store']
        
        report.append(f"Load instructions: {len(loads)}")
        report.append(f"Store instructions: {len(stores)}")
        report.append("")
        
        # Detailed listing
        report.append("Detailed Instruction List:")
        report.append("-" * 30)
        
        for inst in memory_accessing_instructions:
            report.append(f"Line {inst['line_number']}: {inst['timestamp']} ns")
            report.append(f"  PC: {inst['pc']}")
            report.append(f"  Instruction: {inst['instruction']}")
            report.append(f"  Type: {inst['decoded']['type']}")
            report.append(f"  Mnemonic: {inst['decoded'].get('mnemonic', 'N/A')}")
            if inst['memory_address']:
                report.append(f"  Memory Address: {hex(inst['memory_address'])}")
                if inst['memory_region']:
                    report.append(f"  Memory Region: {inst['memory_region'].name}")
            report.append("")
        
        return "\n".join(report)

def main():
    if len(sys.argv) != 3:
        print("Usage: python trace_analyzer.py <trace_file> <memory_map_file>")
        sys.exit(1)
    
    trace_file = sys.argv[1]
    memory_map_file = sys.argv[2]
    
    # Create analyzer
    analyzer = TraceAnalyzer(memory_map_file)
    
    # Analyze trace
    print("Analyzing trace file...")
    memory_instructions = analyzer.analyze_trace_file(trace_file)
    
    # Generate report
    report = analyzer.generate_report(memory_instructions)
    
    # Output report
    print(report)
    
    # Save report to file
    report_file = f"{trace_file}.memory_analysis.txt"
    with open(report_file, 'w') as f:
        f.write(report)
    
    print(f"\nReport saved to: {report_file}")

if __name__ == "__main__":
    main()