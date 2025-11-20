# RISC-V Trace Memory Access Analyzer

This collection of Python scripts analyzes RISC-V instruction traces to identify memory access patterns and map them to defined memory regions.

## Files Provided

1. **`trace_analyzer.py`** - Basic trace analyzer
2. **`enhanced_trace_analyzer.py`** - Advanced analyzer with register state tracking  
3. **`sample_memory_map.json`** - Example memory map file format
4. **`usage_example.py`** - Demo script showing usage

## Features

### Basic Analyzer (`trace_analyzer.py`)
- Parses RISC-V instruction trace files
- Identifies load/store instructions
- Maps memory accesses to defined memory regions
- Generates summary reports

### Enhanced Analyzer (`enhanced_trace_analyzer.py`)
- **Register State Tracking** - Tracks register values throughout execution
- **Accurate Address Calculation** - Computes actual memory addresses accessed
- **Comprehensive Analysis** - Supports more RISC-V instruction types
- **Detailed Reporting** - Provides memory region breakdowns and CSV output

## Input File Formats

### Trace File Format
```
timestamp PC=address, instr=instruction
176000000 PC=00006000, instr=0f40006f
188000000 PC=000060f4, instr=00001197
...
```

### Memory Map JSON Format
```json
{
  "memory_map": {
    "description": "T6 RISC-V Memory Map", 
    "regions": [
      {
        "name": "Instruction Memory",
        "start_addr": "0x00000000",
        "end_addr": "0x0000FFFF", 
        "size": 65536,
        "type": "instruction",
        "description": "Program instruction memory"
      },
      {
        "name": "Data Memory",
        "start_addr": "0x00010000", 
        "end_addr": "0x0001FFFF",
        "size": 65536,
        "type": "data", 
        "description": "General data memory"
      }
    ]
  }
}
```

## Usage

### Basic Usage
```bash
python trace_analyzer.py <trace_file> <memory_map_file>
```

### Enhanced Usage (Recommended)
```bash
python enhanced_trace_analyzer.py <trace_file> <memory_map_file>
```

### Example
```bash
python enhanced_trace_analyzer.py trace.txt memory_map.json
```

## Output Files

The enhanced analyzer generates:

1. **`*_memory_analysis.txt`** - Detailed text report with:
   - Summary statistics (load/store counts)
   - Memory region access breakdown  
   - Address range analysis
   - Detailed instruction listing

2. **`*_memory_accesses.csv`** - CSV file with columns:
   - timestamp, pc, instruction, type, mnemonic, address, region, base_reg, offset

## Supported RISC-V Instructions

### Load Instructions
- `LB` (Load Byte)
- `LH` (Load Halfword) 
- `LW` (Load Word)
- `LBU` (Load Byte Unsigned)
- `LHU` (Load Halfword Unsigned)

### Store Instructions  
- `SB` (Store Byte)
- `SH` (Store Halfword)
- `SW` (Store Word)

### Other Instructions (for register tracking)
- `ADDI` (Add Immediate)
- `ADD` (Add)
- `LUI` (Load Upper Immediate)
- `AUIPC` (Add Upper Immediate to PC)

## Key Features

### 1. RISC-V vs Custom Instruction Detection
The analyzer distinguishes between standard RISC-V instructions and custom instructions based on opcode patterns.

### 2. Register State Tracking
The enhanced version maintains register state throughout execution, enabling accurate calculation of memory addresses for load/store operations.

### 3. Memory Region Mapping
Automatically maps memory accesses to defined regions from the memory map file, providing insights into which parts of memory are being accessed.

### 4. Comprehensive Reporting
- Summary statistics
- Memory region usage patterns
- Detailed per-instruction analysis
- CSV output for further analysis in spreadsheet tools

## Customization

### Adding Custom Instructions
To handle your custom instructions, modify the `is_riscv_instruction()` method to properly identify them:

```python
def is_riscv_instruction(self, instruction: int) -> bool:
    """Check if instruction is RISC-V (vs custom)"""
    opcode = instruction & self.OPCODE_MASK
    
    # Add your custom instruction detection logic
    if self.is_custom_instruction(instruction):
        return False
        
    # Check standard RISC-V opcodes
    riscv_opcodes = {0x03, 0x23, 0x13, 0x33, 0x17, 0x37, 0x63, 0x67, 0x6F}
    return opcode in riscv_opcodes
```

### Adding More RISC-V Instructions
Extend the `execute_instruction()` method to support additional instruction types:

```python
def execute_instruction(self, pc: int, instruction: int) -> Optional[MemoryAccess]:
    opcode = instruction & self.OPCODE_MASK
    
    if opcode == 0x63:  # Branch instructions
        self._execute_branch(pc, instruction)
    # Add more instruction types as needed
```

## Limitations

1. **Register Initialization** - The analyzer assumes registers start at 0, which may not reflect actual execution state
2. **Memory State** - Load instructions update destination registers with dummy values since actual memory content isn't known
3. **Function Calls** - Jump and link instructions aren't fully tracked for register state
4. **Custom Instructions** - Custom instruction effects on register state aren't modeled

## Example Output

```
Enhanced RISC-V Memory Access Analysis
==================================================
Total memory accesses: 15
Load operations: 8  
Store operations: 7

Memory Region Access Count:
  Data Memory: 10
  Stack Memory: 5

Address range: 0x00010000 - 0x00025000

Detailed Memory Access List:
----------------------------------------
  1. Time:  176000000 ns
     PC: 0x00006108
     ADDI -> Address: 0x00015b85
     Region: Data Memory
     Base reg: x10, Offset: 1445
...
```

## Integration with Your Workflow

To integrate with your existing RISC-V and custom instruction decoders:

1. **Replace the decode methods** in the analyzer with calls to your existing decoders
2. **Modify the instruction detection** logic to use your custom vs RISC-V classification
3. **Extend the memory map** format to include your specific memory regions
4. **Add custom instruction handling** for any instructions that affect register state

This provides a solid foundation for analyzing your T6 processor traces while being extensible for your specific needs.