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

#pragma once

#include <absl/container/flat_hash_map.h>
#include <absl/hash/hash.h>
#include <cstring>
#include <vector>

#include "core/cpu/decode.h"
#include "core/cpu/exec.h"
#include "utils/lru_cache.hpp"

class jit_step {
public:
    jit_step();

    rv_insn_t ir;
    size_t len;
    uint64_t pc;
    std::vector<std::pair<uint64_t, size_t>>
        nxt; // possible nxt idx in jit_block

    size_t find_nxt(uint64_t npc) const;
    void add_nxt(uint64_t npc, size_t idx);
};

class jit_block {
public:
    jit_block();
    uint64_t run(bool &invalidate);

    std::vector<jit_step> block;

    // ppv / pa of the compiled code, rounddown(pc)->(rounddown(pa),ppv)
    absl::flat_hash_map<uint64_t, std::pair<uint64_t, uint64_t>> pc_map;
};

class jit_cache : public LruCache<std::pair<uint64_t, uint64_t>, jit_block *,
                                  absl::flat_hash_map> {
public:
    jit_cache()
        : LruCache<std::pair<uint64_t, uint64_t>, jit_block *,
                   absl::flat_hash_map>(_max_size) {}

private:
    static constexpr size_t _max_size = 32000;
};

class jit {
public:
    uint64_t try_run(uint64_t pc);

private:
    jit_block *__compile(uint64_t pc);

    jit_cache _jcache; // Code cache
    absl::flat_hash_map<std::pair<uint64_t, uint64_t>, uint64_t>
        _jhotness; // Task hotness

    static constexpr uint64_t _jhotness_threshold = 96;
};
