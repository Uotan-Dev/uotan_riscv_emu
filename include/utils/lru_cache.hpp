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

#include <list>
#include <unordered_map>

/**
 * O(1) LRU Cache with automatic memory management for pointers.
 * NOT thread-safe - use external synchronization if needed.
 */
template <typename Key, typename Value> class LruCache {
public:
    explicit LruCache(size_t max_size) : _max_size(max_size) {}

    ~LruCache() { clear(); }

    // Disable copy to prevent double-deletion
    LruCache(const LruCache &) = delete;
    LruCache &operator=(const LruCache &) = delete;

    // Insert or update. Deletes old value if key exists. Takes ownership of
    // pointer.
    void put(const Key &key, Value value) {
        auto it = _cache_map.find(key);

        if (it != _cache_map.end()) {
            delete it->second->second; // Delete old pointer
            it->second->second = value;
            _cache_list.splice(_cache_list.begin(), _cache_list, it->second);
            return;
        }

        if (_cache_list.size() >= _max_size) {
            Key lru_key = _cache_list.back().first;
            delete _cache_list.back().second; // Delete evicted pointer
            _cache_list.pop_back();
            _cache_map.erase(lru_key);
        }

        _cache_list.push_front({key, value});
        _cache_map[key] = _cache_list.begin();
    }

    // Get element and mark as recently used. Returns nullptr if not found.
    Value get(const Key &key) {
        auto it = _cache_map.find(key);
        if (it == _cache_map.end()) {
            return nullptr;
        }

        _cache_list.splice(_cache_list.begin(), _cache_list, it->second);
        return it->second->second;
    }

    // Check existence without updating LRU order
    bool contains(const Key &key) const {
        return _cache_map.find(key) != _cache_map.end();
    }

    // Remove element and delete pointer
    bool remove(const Key &key) {
        auto it = _cache_map.find(key);
        if (it == _cache_map.end()) {
            return false;
        }

        delete it->second->second;
        _cache_list.erase(it->second);
        _cache_map.erase(it);
        return true;
    }

    // Clear all elements and delete all pointers
    void clear() {
        for (auto &pair : _cache_list) {
            delete pair.second;
        }
        _cache_map.clear();
        _cache_list.clear();
    }

    size_t size() const { return _cache_list.size(); }

    bool empty() const { return _cache_list.empty(); }

    size_t capacity() const { return _max_size; }

private:
    size_t _max_size;
    std::list<std::pair<Key, Value>> _cache_list; // Front = MRU, Back = LRU
    std::unordered_map<Key, typename std::list<std::pair<Key, Value>>::iterator>
        _cache_map;
};
