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

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Let the CPU step once.
 *
 * This function is usually for debugging and testing purposes.
 */
void cpu_step();

/**
 * @brief Starts normal CPU execution.
 *
 * This function enters the main execution loop and only returns when the
 * machine is shut down by the SiFive test mechanism.
 */
void cpu_start();

/**
 * @brief Starts CPU execution for riscv-arch-test.
 *
 * This function enters the main execution loop and only returns when it has
 * reached the time limit.
 */
void cpu_start_archtest();

/**
 * @brief Prints the state of registers.
 */
void cpu_print_registers();

#ifdef __cplusplus
}
#endif
