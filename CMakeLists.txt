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

set(CMAKE_C_FLAGS_DEBUG   "-g -O0 -Wall -Werror")
set(CMAKE_CXX_FLAGS_DEBUG "-g -O0 -Wall -Werror -Wno-sign-compare")
set(CMAKE_C_FLAGS_RELEASE   "-O3 -Wall -Werror -flto")
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -Wall -Werror -Wno-sign-compare -flto")

# Find SDL2 library
find_package(PkgConfig REQUIRED)
pkg_check_modules(SDL2 REQUIRED sdl2)

# GDB Stub
add_custom_target(gdbstub_build
    COMMAND $(MAKE)
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/mini-gdbstub
    COMMENT "Building libgdbstub.a via Makefile"
)

set(GDBSTUB_LIB ${CMAKE_SOURCE_DIR}/mini-gdbstub/build/libgdbstub.a)

# Find all .c and .cpp files in the src directory.
file(GLOB_RECURSE SOURCES "src/*.c" "src/*.cpp")
list(FILTER SOURCES EXCLUDE REGEX ".*/main\\.c$")
add_library(riscv_sim_lib ${SOURCES})
target_include_directories(riscv_sim_lib PUBLIC include ${SDL2_INCLUDE_DIRS})
target_compile_options(riscv_sim_lib PUBLIC ${SDL2_CFLAGS_OTHER})
set_property(TARGET riscv_sim_lib PROPERTY INTERPROCEDURAL_OPTIMIZATION TRUE)
add_dependencies(riscv_sim_lib gdbstub_build)

# Create the main executable.
file(GLOB_RECURSE APP_SOURCES "src/main.c" "src/main.cpp")
add_executable(uemu ${APP_SOURCES})
target_link_libraries(uemu PRIVATE riscv_sim_lib pthread m readline ncurses ${GDBSTUB_LIB} ${SDL2_LIBRARIES})
target_include_directories(uemu PRIVATE ${SDL2_INCLUDE_DIRS})
target_compile_options(uemu PRIVATE ${SDL2_CFLAGS_OTHER})
set_property(TARGET uemu PROPERTY INTERPROCEDURAL_OPTIMIZATION TRUE)

# --- RISC-V Assembly Build Function ---
function(build_asm asm_path out_path target_name)
    # Create output directories
    file(MAKE_DIRECTORY "${out_path}/bin")
    file(MAKE_DIRECTORY "${out_path}/dumped")
    
    # Find all assembly files
    file(GLOB asm_files "${asm_path}")
    
    set(binary_files)
    set(dump_files)
    
    foreach(file ${asm_files})
        get_filename_component(filename ${file} NAME_WE)
        set(filename_bin "${filename}.bin")
        set(filename_dump "${filename}.dump")
        set(temp_elf "${CMAKE_BINARY_DIR}/temp_${target_name}_${filename}")
        set(output_bin "${out_path}/bin/${filename_bin}")
        set(output_dump "${out_path}/dumped/${filename_dump}")
        
        # Add custom command to compile assembly to ELF
        add_custom_command(
            OUTPUT ${temp_elf}
            COMMAND riscv64-unknown-elf-gcc
                -T${CMAKE_SOURCE_DIR}/riscv-tests/env/v/link.ld
                -I${CMAKE_SOURCE_DIR}/riscv-tests/env/v
                -I${CMAKE_SOURCE_DIR}/riscv-tests/isa/macros/scalar
                -nostdlib -ffreestanding -march=rv64ima_zicsr_zifencei -g -mabi=lp64 -nostartfiles -O0
                -o ${temp_elf}
                ${file}
            DEPENDS ${file}
            COMMENT "Compiling ${filename}.S to ELF for ${target_name}"
            VERBATIM
        )
        
        # Add custom command to convert ELF to binary
        add_custom_command(
            OUTPUT ${output_bin}
            COMMAND riscv64-unknown-elf-objcopy -O binary ${temp_elf} ${output_bin}
            DEPENDS ${temp_elf}
            COMMENT "Converting ${filename} to binary for ${target_name}"
            VERBATIM
        )
        
        # Add custom command to dump assembly
        # add_custom_command(
        #     OUTPUT ${output_dump}
        #     COMMAND riscv64-unknown-elf-objdump --disassemble-all ${temp_elf} > ${output_dump}
        #     DEPENDS ${temp_elf}
        #     COMMENT "Dumping ${filename} assembly for ${target_name}"
        #     VERBATIM
        # )
        
        list(APPEND binary_files ${output_bin})
        list(APPEND dump_files ${output_dump})
    endforeach()
    
    # Create a target that depends on all generated files
    add_custom_target(${target_name} ALL
        # DEPENDS ${binary_files} ${dump_files}
        DEPENDS ${binary_files}
        COMMENT "Building RISC-V assembly tests for ${target_name}"
    )
endfunction()

# Build RISC-V test binaries
build_asm("${CMAKE_SOURCE_DIR}/riscv-tests/isa/rv64mi/*.S"
          "${CMAKE_BINARY_DIR}/testbins/rv64mi"
          "riscv_tests_rv64mi")

build_asm("${CMAKE_SOURCE_DIR}/riscv-tests/isa/rv64si/*.S"
          "${CMAKE_BINARY_DIR}/testbins/rv64si"
          "riscv_tests_rv64si")

build_asm("${CMAKE_SOURCE_DIR}/riscv-tests/isa/rv64ui/*.S"
          "${CMAKE_BINARY_DIR}/testbins/rv64ui"
          "riscv_tests_rv64ui")

build_asm("${CMAKE_SOURCE_DIR}/riscv-tests/isa/rv64um/*.S"
          "${CMAKE_BINARY_DIR}/testbins/rv64um"
          "riscv_tests_rv64um")

build_asm("${CMAKE_SOURCE_DIR}/riscv-tests/isa/rv64ua/*.S"
          "${CMAKE_BINARY_DIR}/testbins/rv64ua"
          "riscv_tests_rv64ua")

# --- Google Test Integration ---
enable_testing()
include(FetchContent)
FetchContent_Declare(
  googletest
  GIT_REPOSITORY https://github.com/google/googletest.git
  GIT_TAG    v1.17.0
)
FetchContent_MakeAvailable(googletest)

# Find all your test source files.
file(GLOB_RECURSE TEST_SOURCES "tests/*.c" "tests/*.cpp")
add_executable(run_tests ${TEST_SOURCES})
target_link_libraries(run_tests PRIVATE riscv_sim_lib GTest::gtest_main readline ncurses ${GDBSTUB_LIB} ${SDL2_LIBRARIES})
target_include_directories(run_tests PRIVATE ${SDL2_INCLUDE_DIRS})
target_compile_options(run_tests PRIVATE ${SDL2_CFLAGS_OTHER})

# Add the test executable to CTest's list of tests.
include(GoogleTest)
gtest_discover_tests(run_tests)

# Make tests depend on RISC-V test binaries
add_dependencies(run_tests riscv_tests_rv64mi)
