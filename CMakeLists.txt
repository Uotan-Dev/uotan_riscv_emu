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

# Compiler flags
set(CMAKE_C_FLAGS_DEBUG   "-g -O0 -Wall -Werror")
set(CMAKE_CXX_FLAGS_DEBUG "-g -O0 -Wall -Werror -Wno-sign-compare")
set(CMAKE_C_FLAGS_RELEASE   "-O3 -Wall -Werror -flto")
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -Wall -Werror -Wno-sign-compare -flto")

# Ensure we have a make program variable (fallback to "make")
if(NOT CMAKE_MAKE_PROGRAM)
  find_program(CMAKE_MAKE_PROGRAM NAMES make gmake)
  if(NOT CMAKE_MAKE_PROGRAM)
    set(CMAKE_MAKE_PROGRAM "make")
  endif()
endif()

# -----------------------------
# Configurable options / cache
# -----------------------------
# Git repo and tag for riscv-isa-sim (Spike). You can override on cmake command line:
# cmake -DSPIKE_GIT_REPO=<url> -DSPIKE_GIT_TAG=<branch-or-commit> ..
set(SPIKE_GIT_REPO "https://github.com/NJU-ProjectN/riscv-isa-sim.git" CACHE STRING "Git repository for riscv-isa-sim (Spike)")
set(SPIKE_GIT_TAG "master" CACHE STRING "Git tag/branch/commit to checkout for riscv-isa-sim")
# Number of parallel jobs for make (used by ExternalProject build)
set(MAKE_JOBS 4 CACHE STRING "Number of parallel jobs to use when building with make")

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
target_include_directories(riscv_sim_lib PUBLIC include)
set_property(TARGET riscv_sim_lib PROPERTY INTERPROCEDURAL_OPTIMIZATION TRUE)
add_dependencies(riscv_sim_lib gdbstub_build)

# Create the main executable.
file(GLOB_RECURSE APP_SOURCES "src/main.c" "src/main.cpp")
add_executable(uemu ${APP_SOURCES})
target_link_libraries(uemu PRIVATE riscv_sim_lib pthread m readline ncurses capstone ${GDBSTUB_LIB})
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

# -----------------------
# Spike (riscv-isa-sim) build via ExternalProject (clone into build dir & build)
# -----------------------
include(ExternalProject)

# Where to clone source and build
set(SPIKE_SRC_DIR ${CMAKE_BINARY_DIR}/riscv-isa-sim-src)
set(SPIKE_BUILD_DIR ${CMAKE_BINARY_DIR}/riscv-isa-sim-build)
set(SPIKE_INSTALL_DIR ${CMAKE_BINARY_DIR}/riscv-isa-sim-install)

# Add ExternalProject to clone & build spike
ExternalProject_Add(spike_project
    PREFIX            spike
    GIT_REPOSITORY    ${SPIKE_GIT_REPO}
    GIT_TAG           ${SPIKE_GIT_TAG}
    SOURCE_DIR        ${SPIKE_SRC_DIR}
    BINARY_DIR        ${SPIKE_BUILD_DIR}

    # run configure from the source's configure script, executed in the build dir
    CONFIGURE_COMMAND ${CMAKE_COMMAND} -E chdir ${SPIKE_BUILD_DIR} ${SPIKE_SRC_DIR}/configure --prefix=${SPIKE_INSTALL_DIR}

    # build using the project's Makefile
    BUILD_COMMAND     ${CMAKE_MAKE_PROGRAM} -C ${SPIKE_BUILD_DIR} -j${MAKE_JOBS}

    # do not run install step (we'll use build tree)
    INSTALL_COMMAND   ""

    # optionally declare byproducts so CMake knows what files are produced
    # (these names are common outputs — adjust if your riscv-isa-sim version differs)
    BUILD_BYPRODUCTS
        ${SPIKE_BUILD_DIR}/spike
        ${SPIKE_BUILD_DIR}/libspike_main.a
        ${SPIKE_BUILD_DIR}/libriscv.a
        ${SPIKE_BUILD_DIR}/libdisasm.a
        ${SPIKE_BUILD_DIR}/libsoftfloat.a
        ${SPIKE_BUILD_DIR}/libfesvr.a
)

# Provide include directories to find spike headers
set(SPIKE_INCLUDE_DIRS
    ${SPIKE_SRC_DIR}
    ${SPIKE_BUILD_DIR}  # some builds put generated headers here
    ${SPIKE_SRC_DIR}/fesvr
    ${SPIKE_SRC_DIR}/riscv
    ${SPIKE_SRC_DIR}/disasm
    ${SPIKE_SRC_DIR}/fdt
    ${SPIKE_SRC_DIR}/softfloat
)

# Build spike-diff (difftest) shared library from nemu/tools/spike-diff/difftest.cpp
set(SPIKE_DIFF_SRC ${CMAKE_SOURCE_DIR}/tools/spike-diff/difftest.cpp)
if(EXISTS ${SPIKE_DIFF_SRC})
    # guest ISA string used by naming convention; change if you have other guest ISAs
    set(GUEST_ISA "rv64")
    set(SPIKE_SO_NAME "${GUEST_ISA}-spike-so")

    add_library(${SPIKE_SO_NAME} SHARED ${SPIKE_DIFF_SRC})

    # It must wait for spike_project to finish
    add_dependencies(${SPIKE_SO_NAME} spike_project)

    # compile settings
    set_target_properties(${SPIKE_SO_NAME} PROPERTIES
        CXX_STANDARD 20
        POSITION_INDEPENDENT_CODE ON
    )
    target_compile_options(${SPIKE_SO_NAME} PRIVATE -O2 -fvisibility=hidden -Wno-error)

    # include spike headers
    target_include_directories(${SPIKE_SO_NAME} PRIVATE ${SPIKE_INCLUDE_DIRS} ${CMAKE_SOURCE_DIR}/include)

    # Link against the static libraries that spike builds.
    # If your riscv-isa-sim build produces libs in different locations, adjust these paths.
    set(SPIKE_LIB_PATHS
        ${SPIKE_BUILD_DIR}/libspike_main.a
        ${SPIKE_BUILD_DIR}/libriscv.a
        ${SPIKE_BUILD_DIR}/libdisasm.a
        ${SPIKE_BUILD_DIR}/libsoftfloat.a
        ${SPIKE_BUILD_DIR}/libfesvr.a
    )

    # Only add libraries that actually exist (to avoid cmake errors during configure)
    set(EXISTING_SPIKE_LIBS "")
    foreach(lib ${SPIKE_LIB_PATHS})
      if(EXISTS ${lib})
        list(APPEND EXISTING_SPIKE_LIBS ${lib})
      endif()
    endforeach()

    # Link. Note: if libs do not exist at configure time, the link may still succeed at build time
    # because spike_project will generate them before ${SPIKE_SO_NAME} is built (add_dependencies was set).
    target_link_libraries(${SPIKE_SO_NAME} PRIVATE ${EXISTING_SPIKE_LIBS})

    # In case the EXTERNAL_BUILD does not write libs to expected paths, advise the user.
    if(EXISTING_SPIKE_LIBS STREQUAL "")
        message(WARNING "No Spike static libs detected at configure time under ${SPIKE_BUILD_DIR}. The build should still work because ${SPIKE_SO_NAME} depends on spike_project, but if linking fails you may need to adjust SPIKE_LIB_PATHS to the actual locations produced by riscv-isa-sim build.")
    endif()
else()
    message(WARNING "Spike difftest source not found at '${SPIKE_DIFF_SRC}'. Skipping target for spike-so.")
endif()

# -----------------------
# Google Test Integration
# -----------------------
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
target_link_libraries(run_tests PRIVATE riscv_sim_lib GTest::gtest_main readline ncurses ${GDBSTUB_LIB})

# Add the test executable to CTest's list of tests.
include(GoogleTest)
gtest_discover_tests(run_tests)

# Make tests depend on RISC-V test binaries
add_dependencies(run_tests riscv_tests_rv64mi)

# Ensure run_tests depends on spike build and spike-diff if present
if(TARGET spike_project)
  add_dependencies(run_tests spike_project)
endif()
if(TARGET ${SPIKE_SO_NAME})
  add_dependencies(run_tests ${SPIKE_SO_NAME})
endif()
