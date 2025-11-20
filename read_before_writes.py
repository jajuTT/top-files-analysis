#!/usr/bin/env python3
import os
import typing
import analysis.enhanced_trace_analyzer as enhanced_trace_analyzer

test_dir_suffix = "_0"

def get_tests(path):
    end_path_with = "rsim/debug"
    if not path.endswith(end_path_with):
        raise Exception(f"- expected the path to end with {end_path_with}, given path: {path}")
    tests: list[str] = []
    for pwd, dirs, _ in os.walk(path):
        for dir_name in dirs:
            if dir_name.endswith(test_dir_suffix):
                tests.append(dir_name[:-(len(test_dir_suffix))])
        break

    return sorted(tests)

def get_test_dir_path(test, path):
    test_dir_name = test + test_dir_suffix
    for pwd, dirs, _ in os.walk(path):
        if test_dir_name in dirs:
            return os.path.join(pwd, test_dir_name)

    return ""

def get_TOP_files(test, path):
    top_files: list[str] = []
    for pwd, _, files in os.walk(get_test_dir_path(test, path)):
        for file_name in files:
            if file_name.startswith("TOP") and file_name.endswith(".trace.txt"):
                top_files.append(os.path.join(pwd, file_name))
        break

    return sorted(top_files)

def get_read_before_writes(path, memory_map_file):
    read_before_writes: dict[str, typing.Any] = dict()
    tests = get_tests(path)
    for test_name in tests:
        top_files = get_TOP_files(test_name, path)
        read_before_writes[test_name] = enhanced_trace_analyzer.detect_all_read_before_write(top_files, memory_map_file)
        # break

    return read_before_writes

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Enhanced RISC-V Trace Analyzer with Register State Tracking",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python read_before_writes.py path_to_rsim_debug memory_map.json
  python read_before_writes.py --rsim-debug-path path_to_rsim_debug --memory-map memory_map.json
        """
    )

    parser.add_argument(
        'rsim_debug_path',
        help='Path to rsim/debug directory of given RTL snapshot'
    )

    parser.add_argument(
        'memory_map_file',
        help='Path to the JSON memory map file'
    )

    args = parser.parse_args()
    read_before_writes = get_read_before_writes(args.rsim_debug_path, args.memory_map_file)
    read_before_writes_addrs: dict[str, list[str]] = dict()
    read_before_writes_mem_regions: dict[str, list[str]] = dict()
    for test_name, info in read_before_writes.items():
        print("- test: ", test_name)
        num_addresses_with_violations = info["summary"]["addresses_with_violations"]
        if num_addresses_with_violations:
            print("  - number of addresses with violations:", info["summary"]["addresses_with_violations"])
            addrs: list[str] = list()
            for addr in sorted(info["address_results"].keys()):
                addr_info = info["address_results"][addr]
                if addr_info["summary"]["has_read_before_write"]:
                    if addr not in read_before_writes_addrs.keys():
                        read_before_writes_addrs[addr] = list()
                    read_before_writes_addrs[addr].append(test_name)
                    addrs.append(addr)
            mem_regions: set[str] = set()
            for addr in addrs:
                mem_region = info["address_results"][addr]["first_access"]["memory_region"]
                mem_regions.add(mem_region)
                msg = f"    - {addr}, {mem_region}"
                print(msg)

            for mem_region in mem_regions:
                if mem_region not in read_before_writes_mem_regions.keys():
                    read_before_writes_mem_regions[mem_region] = list()
                read_before_writes_mem_regions[mem_region].append(test_name)

    print("- Read before write memory addresses and number of tests")
    for addr, tests in read_before_writes_addrs.items():
        read_before_writes_addrs[addr] = sorted(tests)

    read_before_writes_addrs = dict(sorted(read_before_writes_addrs.items()))
    memory_map_dict = enhanced_trace_analyzer.get_memory_map_dict(args.memory_map_file)
    for addr, tests in read_before_writes_addrs.items():
        print(f"  - address: {addr}, memory_region = {enhanced_trace_analyzer.find_smallest_memory_region(int(addr, 0), memory_map_dict)}, number of tests: {len(tests)}")

    print("- Read before write memory regions and number of tests")
    for mem_region, tests in read_before_writes_mem_regions.items():
        read_before_writes_mem_regions[mem_region] = sorted(tests)

    read_before_writes_mem_regions = dict(sorted(read_before_writes_mem_regions.items(), key=lambda x: x[0] if x[0] is not None else ""))
    memory_map_dict = enhanced_trace_analyzer.get_memory_map_dict(args.memory_map_file)
    for mem_region, tests in read_before_writes_mem_regions.items():
        num_addresses = sum([1 for addr in read_before_writes_addrs.keys() if enhanced_trace_analyzer.find_smallest_memory_region(int(addr, 0), memory_map_dict) == mem_region])
        print(f"  - memory_region: {mem_region}, num_addresses = {num_addresses}, number of tests: {len(tests)}")





        # if info["summary"]["addresses_with_violations"]:
        #     print("  - addresses with violations:", info["summary"]["addresses_with_violations"])
        # has_
        # print("  - addresses with read before write: ")
        # for addr in sorted(info["address_results"].keys()):
        #     addr_info = info["address_results"][addr]
        #     if addr_info["summary"]["has_read_before_write"]:
        #         print("- addr: ", addr)
        # print("  - addresses in violation: ", sorted(info["address_results"].keys()), "num keys = ", len(info["address_results"].keys()))
        # print("  - info['summary']: ", info['summary'])