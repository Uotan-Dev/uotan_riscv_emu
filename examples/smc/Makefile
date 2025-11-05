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

CROSS ?= riscv64-unknown-elf-
CC_RISCV = $(CROSS)gcc
LD_RISCV = $(CROSS)ld
OBJCOPY = $(CROSS)objcopy
OBJDUMP = $(CROSS)objdump

CFLAGS_RISCV = -march=rv64im_zicsr_zifencei -mabi=lp64 -O0 -fno-common -fno-builtin \
               -nostdlib -ffreestanding -fno-pic -mstrict-align
LDFLAGS = -T link.ld

.PHONY: all clean dump

all: firmware.bin

firmware.elf: smc_test.o link.ld
	$(CC_RISCV) $(CFLAGS_RISCV) -o $@ smc_test.o $(LDFLAGS)

smc_test.o: smc_test.S
	$(CC_RISCV) $(CFLAGS_RISCV) -c smc_test.S -o smc_test.o

firmware.bin: firmware.elf
	$(OBJCOPY) -O binary firmware.elf firmware.bin
	@echo "=========================================="
	@echo "Produced firmware.bin (load at 0x80000000)"
	@echo "Expected result: t1 = 499500 (0x79F6C)"
	@echo "=========================================="

dump: firmware.elf
	$(OBJDUMP) -d firmware.elf > firmware.dump
	@echo "Disassembly saved to firmware.dump"

clean:
	rm -f *.o firmware.elf firmware.bin firmware.dump
