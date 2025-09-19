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

# Set the minimum required version of CMake.
cmake_minimum_required(VERSION 3.14)

project(riscv_sim VERSION 1.0 LANGUAGES C CXX)

# Set the C++ standard to C++20.
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 17)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(CMAKE_C_FLAGS_DEBUG   "-g -O0")
set(CMAKE_CXX_FLAGS_DEBUG "-g -O0")
set(CMAKE_C_FLAGS_RELEASE   "-O3")
set(CMAKE_CXX_FLAGS_RELEASE "-O3")

# Find all .c and .cpp files in the src directory.
file(GLOB_RECURSE SOURCES "src/*.c" "src/*.cpp")
list(FILTER SOURCES EXCLUDE REGEX ".*/main\\.c$")
add_library(riscv_sim_lib ${SOURCES})
target_include_directories(riscv_sim_lib PUBLIC include)

set_property(TARGET riscv_sim_lib PROPERTY INTERPROCEDURAL_OPTIMIZATION TRUE)

# Create the main executable.
file(GLOB_RECURSE APP_SOURCES "src/main.c" "src/main.cpp")
add_executable(riscv-sim ${APP_SOURCES})
target_link_libraries(riscv-sim PRIVATE riscv_sim_lib pthread m readline ncurses)
set_property(TARGET riscv-sim PROPERTY INTERPROCEDURAL_OPTIMIZATION TRUE)

# --- Google Test Integration ---
enable_testing()

include(FetchContent)
FetchContent_Declare(
  googletest
  GIT_REPOSITORY https://github.com/google/googletest.git
  GIT_TAG    v1.14.0
)
FetchContent_MakeAvailable(googletest)

# Find all your test source files.
file(GLOB_RECURSE TEST_SOURCES "tests/*.c" "tests/*.cpp")

add_executable(run_tests ${TEST_SOURCES})
target_link_libraries(run_tests PRIVATE riscv_sim_lib GTest::gtest_main)

# Add the test executable to CTest's list of tests.
include(GoogleTest)
gtest_discover_tests(run_tests)
