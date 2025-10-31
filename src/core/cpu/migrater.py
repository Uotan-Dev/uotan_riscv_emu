#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import sys

def parse_instpat(content):
    """Parse INSTPAT entries to extract instruction names"""
    instructions = []
    
    # Match INSTPAT pattern to extract instruction name
    # Pattern: INSTPAT("...", inst_name, ...)
    pattern = r'INSTPAT\s*\(\s*"[^"]+"\s*,\s*(\w+(?:\.\w+)?)\s*,'
    
    matches = re.finditer(pattern, content)
    
    for match in matches:
        inst_name = match.group(1)
        if inst_name not in [inst['name'] for inst in instructions]:
            instructions.append({'name': inst_name})
    
    return instructions

def generate_exec_functions(instructions):
    """Generate empty exec function shells"""
    output = []
    
    for inst in instructions:
        func_name = f"exec_{inst['name'].replace('.', '_')}"
        
        func = f"void {func_name}(Decode *s) {{\n"
        func += "    EXTRACT_OPRAND();\n"
        func += "\n"
        func += "}"
        
        output.append(func)
    
    # Join with blank line between functions
    return '\n\n'.join(output)

def generate_instruction_macro(instructions):
    """Generate instruction macro list"""
    inst_names = [inst['name'].replace('.', '_') for inst in instructions]
    
    # Build macro with proper formatting
    macro = "#define RISCV_INSTRUCTIONS(f) \\\n"
    
    # Group instructions, 8 per line for readability
    line_width = 8
    for i in range(0, len(inst_names), line_width):
        line_insts = inst_names[i:i+line_width]
        line = "  " + " ".join([f"f({name})" for name in line_insts])
        
        # Add backslash continuation if not the last line
        if i + line_width < len(inst_names):
            line += " \\"
        
        macro += line + "\n"
    
    return macro.rstrip()

def main():
    if len(sys.argv) < 2:
        input_file = 'input.txt'
        output1_file = 'output1.txt'
        output2_file = 'output2.txt'
    else:
        input_file = sys.argv[1]
        output1_file = sys.argv[2] if len(sys.argv) > 2 else 'output1.txt'
        output2_file = sys.argv[3] if len(sys.argv) > 3 else 'output2.txt'
    
    try:
        # Read input file
        with open(input_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Parse INSTPAT entries
        instructions = parse_instpat(content)
        
        if not instructions:
            print("Warning: No INSTPAT entries found")
            return
        
        print(f"Successfully parsed {len(instructions)} instructions")
        
        # Generate output1.txt - exec function shells
        exec_functions = generate_exec_functions(instructions)
        with open(output1_file, 'w', encoding='utf-8') as f:
            f.write(exec_functions)
            f.write('\n')  # Add final newline
        print(f"Generated {output1_file}")
        
        # Generate output2.txt - instruction macro
        inst_macro = generate_instruction_macro(instructions)
        with open(output2_file, 'w', encoding='utf-8') as f:
            f.write(inst_macro)
            f.write('\n')  # Add final newline
        print(f"Generated {output2_file}")
        
        # Print parsed instruction names
        print("\nParsed instructions:")
        for inst in instructions:
            print(f"  - {inst['name']}")
        
    except FileNotFoundError:
        print(f"Error: File not found {input_file}")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    main()
