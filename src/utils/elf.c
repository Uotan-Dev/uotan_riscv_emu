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

#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "core/mem.h"
#include "utils/elf.h"
#include "utils/logger.h"

bool is_elf(const char *path) {
    FILE *fp = fopen(path, "rb");
    if (!fp) {
        log_error("is_elf: fopen");
        exit(EXIT_FAILURE);
    }
    unsigned char e_ident[4];
    bool result = false;
    if (fread(e_ident, 1, 4, fp) == 4) {
        if (memcmp(e_ident, ELFMAG, 4) == 0) {
            result = true;
        }
    }
    fclose(fp);
    return result;
}

static const Elf64_Shdr *get_section_header(const uint8_t *file_data,
                                            const char *name) {
    const Elf64_Ehdr *hdr = (const Elf64_Ehdr *)file_data;
    const Elf64_Shdr *sh_tbl = (const Elf64_Shdr *)(file_data + hdr->e_shoff);
    const char *sh_str_tbl =
        (const char *)(file_data + sh_tbl[hdr->e_shstrndx].sh_offset);

    for (int i = 0; i < hdr->e_shnum; i++) {
        const char *sname = &sh_str_tbl[sh_tbl[i].sh_name];
        if (strcmp(name, sname) == 0)
            return &sh_tbl[i];
    }
    return NULL;
}

static const Elf64_Sym *get_symbol(const uint8_t *file_data, const char *name) {
    const Elf64_Shdr *sym_hdr = get_section_header(file_data, ".symtab");
    const Elf64_Shdr *str_hdr = get_section_header(file_data, ".strtab");

    if (!sym_hdr || !str_hdr)
        return NULL;

    const Elf64_Sym *sym_tbl =
        (const Elf64_Sym *)(file_data + sym_hdr->sh_offset);
    const char *str_tbl = (const char *)(file_data + str_hdr->sh_offset);
    int sym_count = sym_hdr->sh_size / sizeof(Elf64_Sym);

    for (int i = 0; i < sym_count; i++) {
        const char *sym_name = &str_tbl[sym_tbl[i].st_name];
        if (strcmp(name, sym_name) == 0)
            return &sym_tbl[i];
    }
    return NULL;
}

uint64_t elf_load(const char *file_path) {
    int fd = open(file_path, O_RDONLY);
    if (fd < 0) {
        log_error("Failed to open ELF file: %s", file_path);
        exit(EXIT_FAILURE);
    }

    struct stat st;
    fstat(fd, &st);
    uint8_t *file_data = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);

    const Elf64_Ehdr *hdr = (const Elf64_Ehdr *)file_data;

    // Validate ELF header
    if (hdr->e_ident[EI_CLASS] != ELFCLASS64 || hdr->e_machine != EM_RISCV) {
        log_error("Invalid ELF file format for RV64.");
        exit(EXIT_FAILURE);
    }

    // Load segments
    const Elf64_Phdr *phdr = (const Elf64_Phdr *)(file_data + hdr->e_phoff);
    for (int i = 0; i < hdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_LOAD) {
            uint64_t paddr = phdr[i].p_paddr;
            size_t filesz = phdr[i].p_filesz;
            size_t memsz = phdr[i].p_memsz;
            uint64_t offset = phdr[i].p_offset;

            if (paddr_in_pmem(paddr) && paddr_in_pmem(paddr + memsz - 1)) {
                // Copy from file to memory
                memcpy(GUEST_TO_HOST(paddr), file_data + offset, filesz);
                // Zero out the rest of the segment (BSS)
                if (memsz > filesz)
                    memset(GUEST_TO_HOST(paddr + filesz), 0, memsz - filesz);
            }
        }
    }

    uint64_t entry_point = hdr->e_entry;
    munmap(file_data, st.st_size);
    return entry_point;
}

void dump_signature(const char *elf_file_path, const char *sig_file_path) {
    int fd = open(elf_file_path, O_RDONLY);
    if (fd < 0)
        return;

    struct stat st;
    fstat(fd, &st);
    uint8_t *file_data = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);

    const Elf64_Sym *begin_sym = get_symbol(file_data, "begin_signature");
    const Elf64_Sym *end_sym = get_symbol(file_data, "end_signature");

    if (!begin_sym || !end_sym) {
        log_error("Signature symbols not found in ELF.");
        munmap(file_data, st.st_size);
        return;
    }

    uint64_t start_addr = begin_sym->st_value;
    uint64_t end_addr = end_sym->st_value;

    FILE *f = fopen(sig_file_path, "w");
    if (!f) {
        log_error("Cannot open signature output file: %s", sig_file_path);
        munmap(file_data, st.st_size);
        return;
    }

    // Dump word by word
    for (uint64_t addr = start_addr; addr < end_addr; addr += 4) {
        uint32_t w = *(uint32_t *)(GUEST_TO_HOST(addr));
        fprintf(f, "%08x\n", w);
    }

    fclose(f);
    munmap(file_data, st.st_size);
    log_info("Signature dumped to %s", sig_file_path);
}
