"""Test IDAPython script for integration testing.

Lists all functions with their sizes and prints a summary.
"""
import idautils
import ida_funcs

count = 0
for ea in idautils.Functions():
    func = ida_funcs.get_func(ea)
    if func:
        size = func.size()
        name = ida_funcs.get_func_name(ea)
        print(f"{name} @ {ea:#x} size={size}")
        count += 1

print(f"total_functions={count}")
