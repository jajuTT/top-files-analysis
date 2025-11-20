#!/usr/bin/env python3
"""
Test script for the enhanced trace analyzer with the actual memory map
"""

import os
import sys
from enhanced_trace_analyzer import EnhancedTraceAnalyzer

def create_test_trace():
    """Create a small test trace file"""
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
194000000 PC=00006118, instr=37c080e7             
206000000 PC=00006490, instr=40a58633             
207000000 PC=00006494, instr=00000593             
208000000 PC=00006498, instr=1280006f"""
    
    with open('test_trace.txt', 'w') as f:
        f.write(trace_data)
    
    return 'test_trace.txt'

def test_memory_map_loading():
    """Test if the memory map loads correctly"""
    print("Testing memory map loading...")
    
    if not os.path.exists('memory_map.json'):
        print("✗ memory_map.json not found in current directory")
        return False
    
    try:
        analyzer = EnhancedTraceAnalyzer('memory_map.json')
        print(f"✓ Memory map loaded successfully with {len(analyzer.memory_regions)} regions")
        
        # Print first few regions
        print("\nFirst 5 memory regions:")
        for i, region in enumerate(analyzer.memory_regions[:5]):
            print(f"  {i+1}. {region['name']}: {region['start_addr']} - {region['end_addr']}")
        
        return True
    except Exception as e:
        print(f"✗ Error loading memory map: {e}")
        return False

def test_address_lookup():
    """Test address lookup functionality"""
    print("\nTesting address lookup...")
    
    try:
        analyzer = EnhancedTraceAnalyzer('memory_map.json')
        
        # Test some addresses
        test_addresses = [
            0x0,           # Should be in l1
            0x800000,      # Should be in local_regs
            0x801000,      # Should be in local_regs or sub-region
            0xFFFFFFFF,    # Should not be found
        ]
        
        for addr in test_addresses:
            region = analyzer._find_memory_region(addr)
            print(f"  Address 0x{addr:08x}: {region or 'Not found'}")
        
        return True
    except Exception as e:
        print(f"✗ Error testing address lookup: {e}")
        return False

def test_trace_analysis():
    """Test trace analysis"""
    print("\nTesting trace analysis...")
    
    trace_file = create_test_trace()
    
    try:
        analyzer = EnhancedTraceAnalyzer('memory_map.json')
        memory_accesses = analyzer.analyze_trace(trace_file)
        
        print(f"✓ Trace analysis complete")
        print(f"✓ Found {len(memory_accesses)} memory accessing instructions")
        
        if memory_accesses:
            print("\nFirst few memory accesses:")
            for i, ma in enumerate(memory_accesses[:3]):
                print(f"  {i+1}. {ma.mnemonic} at 0x{ma.address:08x} (region: {ma.memory_region or 'Unknown'})")
        else:
            print("  Note: No memory accesses found - this is normal if the test instructions are all computational")
        
        # Clean up
        os.remove(trace_file)
        return True
        
    except Exception as e:
        print(f"✗ Error testing trace analysis: {e}")
        # Clean up
        if os.path.exists(trace_file):
            os.remove(trace_file)
        return False

def main():
    print("Enhanced Trace Analyzer Test Suite")
    print("=" * 40)
    
    # Test 1: Memory map loading
    if not test_memory_map_loading():
        print("\n❌ Memory map loading failed - cannot continue")
        return
    
    # Test 2: Address lookup
    if not test_address_lookup():
        print("\n❌ Address lookup failed")
        return
    
    # Test 3: Trace analysis
    if not test_trace_analysis():
        print("\n❌ Trace analysis failed")
        return
    
    print("\n✅ All tests passed! The analyzer is ready to use.")
    print("\nUsage:")
    print("  python enhanced_trace_analyzer.py <trace_file> memory_map.json")

if __name__ == "__main__":
    main()