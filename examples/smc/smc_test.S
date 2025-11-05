# Copyright 2025 Nuo Shen, Nanjing University
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# RISC-V 64-bit Self-Modifying Code (SMC)
# M-mode bare-metal software, 1000 iterations
# Modifies addi instruction's immediate value each iteration

.section .text
.globl _start

_start:
    li t0, 1000          # iteration counter, t0 = 1000
    li t1, 0             # accumulator, t1 = 0
    la t2, target_instr  # get address of instruction to modify
    li t3, 0             # current immediate value, starts at 0

loop:
    # Execute target instruction
target_instr:
    addi t1, t1, 0       # initial: t1 = t1 + 0 (this instruction will be modified)
    
    addi t3, t3, 1       # increment immediate value
    
    # Construct new instruction
    slli t4, t3, 20
    li t5, 0x00030313
    or t4, t4, t5
    
    # Write new instruction
    sw t4, 0(t2)
    
    addi t0, t0, -1 
    bnez t0, loop

    # Loop finished, t1 contains final result
    # Result = 0 + 1 + 2 + 3 + ... + 999 = 499500
    
    # Move result to a0
    addi a0, t1, 0

halt:
    lui t2, 0x100
    li t0, 0x5555
    sw t0, 0(t2)
    wfi
    j halt
