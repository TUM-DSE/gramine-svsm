#!/bin/bash

input_file="gdb.log"

# Extract function names, sort them, and get unique names
grep "called" "$input_file" | awk '{print $1}' | sort | uniq -c | sort -nr
