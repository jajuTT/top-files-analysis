#!/usr/bin/env python3
"""
Simple usage example for the RISC-V trace analyzer
"""

import sys
import os

# Add the directory containing our analyzer scripts to the path
sys.path.append('/tmp')

from enhanced_trace_analyzer import EnhancedTraceAnalyzer

def create_sample_trace():
    """Create a sample trace file from the provided data"""
    trace_data = """176000000 PC=00006000, instr=0f40006f             
188000000 PC=000060f4, instr=00001197             
188000000 PC=000060f8, instr=da818193             
189000000 PC=000060fc, instr=007fc117             
190000000 PC=00006100, instr=30410113             
190000000 PC=00006104, instr=00000517             
191000000 PC=00006108, instr=5b850513             
192000000 PC=0000610c, instr=00000597             
192000000 PC=00006110, instr=5b058593             
193000000 PC=00006114, instr=00000097             
194000000 PC=00006118, instr=37c080e7"""
    
    with open('/tmp/sample_trace.txt', 'w') as f:
        f.write(trace_data)
    
    return '/tmp/sample_trace.txt'

def main():
    print("RISC-V Trace Analyzer Demo")
    print("=" * 30)
    
    # Create sample files
    trace_file = create_sample_trace()
    memory_map_file = '/tmp/sample_memory_map.json'
    
    print(f"Using trace file: {trace_file}")
    print(f"Using memory map: {memory_map_file}")
    print()
    
    # Create analyzer
    try:
        analyzer = EnhancedTraceAnalyzer(memory_map_file)
        print("✓ Memory map loaded successfully")
    except Exception as e:
        print(f"✗ Error loading memory map: {e}")
        return
    
    # Analyze trace
    try:
        memory_accesses = analyzer.analyze_trace(trace_file)
        print(f"✓ Trace analysis complete")
        print(f"✓ Found {len(memory_accesses)} memory accessing instructions")
    except Exception as e:
        print(f"✗ Error analyzing trace: {e}")
        return
    
    # Generate report
    if memory_accesses:
        report = analyzer.generate_detailed_report(memory_accesses)
        print("\n" + report)
    else:
        print("\nNo memory-accessing RISC-V instructions found in the trace sample.")
        print("This could be because:")
        print("- The instructions are all computation/control flow")
        print("- They are custom (non-RISC-V) instructions") 
        print("- Register tracking hasn't been initialized properly")

if __name__ == "__main__":
    main()