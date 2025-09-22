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

CROSS ?= riscv64-linux-gnu-
CC_RISCV = $(CROSS)gcc
LD_RISCV = $(CROSS)ld
OBJCOPY = $(CROSS)objcopy
CFLAGS_RISCV = -march=rv64im_zicsr -mabi=lp64 -O0 -mcmodel=medany -fno-common -fno-builtin -nostdlib -ffreestanding -fno-pic -mstrict-align
LDFLAGS = -T link.ld

.PHONY: all clean

all: firmware.bin

# build firmware.elf then convert to bin
firmware.elf: boot.o app.o link.ld
	$(CC_RISCV) $(CFLAGS_RISCV) -o $@ boot.o app.o $(LDFLAGS)

boot.o: boot.S
	$(CC_RISCV) $(CFLAGS_RISCV) -c boot.S -o boot.o

app.o: app.c
	$(CC_RISCV) $(CFLAGS_RISCV) -c app.c -o app.o

firmware.bin: firmware.elf
	$(OBJCOPY) -O binary firmware.elf firmware.bin
	@echo "Produced firmware.bin (to be loaded at 0x80000000)"

clean:
	rm -f *.o firmware.elf firmware.bin
