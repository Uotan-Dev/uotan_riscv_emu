/*
 * Copyright 2025 Nuo Shen, Nanjing University
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* link.ld - RISC-V Linker Script for SV39 Test */

OUTPUT_ARCH("riscv")
ENTRY(_start)

SECTIONS
{
  /* Start at 0x80000000 - standard RISC-V physical memory base */
  . = 0x80000000;

  /* Text section - code and read-only data */
  .text : {
    KEEP(*(.text._start))
    KEEP(*(.text*))
    *(.rodata*)
  }

  /* Ensure data section is aligned */
  . = ALIGN(8);

  /* Data section - initialized data */
  .data : {
    __data_start = .;
    *(.data*)
    *(.sdata*)
    __data_end = .;
  }

  /* BSS section - uninitialized data */
  . = ALIGN(8);
  .bss : {
    __bss_start = .;
    *(.bss*)
    *(.sbss*)
    *(COMMON)
    . = ALIGN(8);
    __bss_end = .;
  }

  /* Global pointer for optimized access to small data */
  . = ALIGN(8);
  __global_pointer$ = . + 0x800;

  /* Stack grows downward from this address */
  /* Allocate 128KB for stack */
  . = ALIGN(16);
  . = . + 0x20000;
  __stack_top = .;

  /* End of program */
  _end = .;
  PROVIDE(end = .);
}
