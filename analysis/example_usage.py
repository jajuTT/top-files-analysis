#!/usr/bin/env python3
"""
Example usage of the enhanced trace analyzer showing both file-based and dict-based approaches.
"""

from enhanced_trace_analyzer import analyze_trace_files, analyze_trace_with_memory_map

def example_file_based_analysis():
    """Example using file-based memory map"""
    print("=== File-based Analysis ===")
    trace_file = "sample_trace.txt" 
    memory_map_file = "memory_map.json"
    
    # This loads memory map from JSON file
    analyze_trace_files(trace_file, memory_map_file)

def example_dict_based_analysis():
    """Example using dictionary-based memory map"""
    print("\n=== Dictionary-based Analysis ===")
    trace_file = "sample_trace.txt"
    
    # Define memory map as dictionary - this could come from any source
    memory_map_dict = {
        "trisc_map": {
            "DRAM": {
                "KEY": "DRAM",
                "START": "0x80000000",
                "END": "0x8FFFFFFF", 
                "NUM_BYTES_PER_REGISTER": 4,
                "RESIDES_WITHIN": []
            },
            "MMIO": {
                "KEY": "MMIO", 
                "START": "0x10000000",
                "END": "0x1FFFFFFF",
                "NUM_BYTES_PER_REGISTER": 4,
                "RESIDES_WITHIN": []
            },
            "ROM": {
                "KEY": "ROM",
                "START": "0x00000000", 
                "END": "0x0FFFFFFF",
                "NUM_BYTES_PER_REGISTER": 4,
                "RESIDES_WITHIN": []
            }
        }
    }
    
    # This uses memory map from dictionary - returns results for further processing
    memory_accesses, report = analyze_trace_with_memory_map(
        trace_file, 
        memory_map_dict, 
        output_prefix="dict_based_analysis"
    )
    
    print(f"\nReturned {len(memory_accesses)} memory accesses for further processing")
    
    # You can now do additional processing with the results
    dram_accesses = [ma for ma in memory_accesses if ma.memory_region == "DRAM"]
    mmio_accesses = [ma for ma in memory_accesses if ma.memory_region == "MMIO"] 
    
    print(f"DRAM accesses: {len(dram_accesses)}")
    print(f"MMIO accesses: {len(mmio_accesses)}")

def example_programmatic_usage():
    """Example of building memory map programmatically"""
    print("\n=== Programmatic Memory Map Construction ===")
    
    # Build memory map from configuration or other sources
    memory_regions = {
        "SRAM": {"start": 0x20000000, "end": 0x2000FFFF},
        "FLASH": {"start": 0x08000000, "end": 0x080FFFFF}, 
        "PERIPH": {"start": 0x40000000, "end": 0x4000FFFF}
    }
    
    # Convert to expected format
    memory_map_dict = {"trisc_map": {}}
    
    for name, config in memory_regions.items():
        memory_map_dict["trisc_map"][name] = {
            "KEY": name,
            "START": f"0x{config['start']:08X}",
            "END": f"0x{config['end']:08X}",
            "NUM_BYTES_PER_REGISTER": 4,
            "RESIDES_WITHIN": []
        }
    
    print("Constructed memory map:")
    for region, data in memory_map_dict["trisc_map"].items():
        print(f"  {region}: {data['START']} - {data['END']}")
    
    # Use the constructed map
    trace_file = "sample_trace.txt"
    try:
        memory_accesses, report = analyze_trace_with_memory_map(
            trace_file, 
            memory_map_dict,
            output_prefix="programmatic_analysis"
        )
    except FileNotFoundError:
        print(f"Note: {trace_file} not found - this is just an example")

if __name__ == "__main__":
    print("Enhanced Trace Analyzer Usage Examples")
    print("=" * 50)
    
    # Show different usage patterns
    try:
        example_file_based_analysis()
    except FileNotFoundError:
        print("File-based example skipped - files not found")
    
    try:
        example_dict_based_analysis() 
    except FileNotFoundError:
        print("Dict-based example skipped - trace file not found")
    
    example_programmatic_usage()
    
    print("\n=== Summary ===")
    print("Two main functions available:")
    print("1. analyze_trace_files(trace_file, memory_map_file)")
    print("   - Loads memory map from JSON file")
    print("   - Good for command-line usage")
    print("")
    print("2. analyze_trace_with_memory_map(trace_file, memory_map_dict, output_prefix)")
    print("   - Takes memory map as dictionary")
    print("   - Returns (memory_accesses, report) for further processing")
    print("   - Good for programmatic usage and integration")