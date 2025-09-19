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

#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

#include "test_utils.hpp"

bool create_dir(const std::string &path) {
    try {
        if (path.empty())
            return false;
        return std::filesystem::create_directories(path) ||
               std::filesystem::exists(path);
    } catch (const std::exception &e) {
        std::cerr << "create_dir error: " << e.what() << '\n';
        return false;
    }
}

bool write_file(const std::string &content, const std::string &path) {
    try {
        if (path.empty())
            return false;
        std::filesystem::path p(path);
        auto parent = p.parent_path();
        if (!parent.empty() && !std::filesystem::exists(parent)) {
            if (!create_dir(parent.string()))
                return false;
        }

        std::ofstream ofs(path, std::ios::binary);
        if (!ofs)
            return false;
        ofs << content;
        return ofs.good();
    } catch (const std::exception &e) {
        std::cerr << "write_file error: " << e.what() << '\n';
        return false;
    }
}

int run_process(const std::vector<std::string> &argv_vec) {
    if (argv_vec.empty())
        return -1;

    std::vector<char *> argv;
    argv.reserve(argv_vec.size() + 1);
    for (const auto &s : argv_vec)
        argv.push_back(const_cast<char *>(s.c_str()));
    argv.push_back(nullptr);

    pid_t pid = fork();
    if (pid < 0) {
        std::perror("fork");
        return -1;
    }
    if (pid == 0) {
        // child
        execvp(argv[0], argv.data());
        // execvp only returns on error
        std::cerr << "execvp failed: " << argv[0] << " : " << strerror(errno)
                  << "\n";
        exit(127);
    }

    // parent: wait
    int status = 0;
    if (waitpid(pid, &status, 0) < 0) {
        std::perror("waitpid");
        return -1;
    }
    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    } else if (WIFSIGNALED(status)) {
        std::cerr << "process killed by signal " << WTERMSIG(status) << "\n";
        return 128 + WTERMSIG(status);
    }
    return -1;
}