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

#include <asmjit/x86.h>

#include "jit_v1.hpp"

using jit_v2_func = uint64_t (*)(bool *);

class jit_v2_block {
public:
    explicit jit_v2_block(asmjit::JitRuntime &jrt);
    ~jit_v2_block();

    uint64_t run(bool &invalidate);
    void set(jit_v2_func jf);

    // ppv / pa of the compiled code, rounddown(pc)->(rounddown(pa),ppv)
    absl::flat_hash_map<uint64_t, std::pair<uint64_t, uint64_t>> pc_map;

private:
    jit_v2_func _jf;
    asmjit::JitRuntime &jrt;
};

class jit_v2_cache : public LruCache<std::pair<uint64_t, uint64_t>,
                                     jit_v2_block *, absl::flat_hash_map> {
public:
    jit_v2_cache()
        : LruCache<std::pair<uint64_t, uint64_t>, jit_v2_block *,
                   absl::flat_hash_map>(_max_size) {}

private:
    static constexpr size_t _max_size = 32000;
};

class jit_v2 {
public:
    explicit jit_v2(jit_v1 &jv1) : _jv1(jv1) {}

    uint64_t try_run(uint64_t pc);

private:
    jit_v2_block *__compile(const jit_v1_block &jb_v1);

    jit_v2_cache _jcache; // Code cache
    absl::flat_hash_map<std::pair<uint64_t, uint64_t>, uint64_t>
        _jhotness; // Task hotness
    asmjit::JitRuntime _jrt;

    jit_v1 &_jv1;

    static constexpr uint64_t _jhotness_threshold = 640;
};
