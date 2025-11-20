#!/usr/bin/env python

import enhanced_trace_analyzer
import sys

def main():
    if len(sys.argv) < 3:
        print("- error: one or more command line arguments missing")
        exit(1)
    dir_path = sys.argv[1]
    memory_file_path = sys.argv[2]

    enhanced_trace_analyzer.analyze_trace_files_from_dir(dir_path, memory_file_path)

if __name__ == "__main__":
    main()