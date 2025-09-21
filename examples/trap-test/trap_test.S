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

    .section .text
    .align  2
    .global _start

_start:
    # Set up the trap handler address
    la t0, trap_handler
    csrw mtvec, t0

    # Put a known value in a0 before the trap
    li a0, 10

    ecall

    # After returning from the trap, we should land here.
    # The value in a0 should now be 10 + 42 = 52.
done:
    ebreak # Trigger a break point
    j done

trap_handler:
    # Add 42 to a0 to signal that we were here.
    addi a0, a0, 42
    
    # Add 4 to mepc for next instruction
    csrr t1, mepc
    addi t1, t1, 4
    csrw mepc, t1

    mret
