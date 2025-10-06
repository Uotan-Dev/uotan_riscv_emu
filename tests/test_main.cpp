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

#include <gtest/gtest.h>
#include <iostream>

#include "utils/alarm.h"

class UemuEnv : public ::testing::Environment {
public:
    void SetUp() override {
        std::cout << "[UemuEnv] Init" << std::endl;
        alarm_init();
    }

    void TearDown() override {
        std::cout << "[UemuEnv] CleanUp" << std::endl;
    }
};

int main(int argc, char *argv[]) {
    ::testing::InitGoogleTest(&argc, argv);
    ::testing::AddGlobalTestEnvironment(new UemuEnv);
    return RUN_ALL_TESTS();
}
