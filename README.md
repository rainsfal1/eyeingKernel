# Kernel System Call Interceptor

## Description
This kernel module intercepts system calls and allows for monitoring processes that invoke specific system calls. It provides a mechanism for:
- Intercepting system calls
- Monitoring specific PIDs for intercepted system calls
- Logging system call usage
- Automatically removing a process from monitoring when it exits

The module modifies the system call table to replace selected system calls with custom implementations.

## Features
- **Intercept Syscalls**: Replace a system call with a custom handler.
- **Monitor PIDs**: Track system call invocations for specific processes (PIDs).
- **Log System Calls**: Log specific system call parameters.
- **Exit Group Interception**: Automatically removes a process from the monitoring list when it exits.

## File Structure
- **`interceptor.c`**: The main source file implementing system call interception, monitoring, and logging.
- **`interceptor.h`**: Header file defining constants and structures used in the module.
- **`test_intercept.c`**: Testing module for the interceptor.
- **`Kbuild`**: Build configuration for the kernel module.
- **`Makefile`**: Makefile for compiling the kernel module.

## Prerequisites
- **Linux Kernel Development Setup**: Ensure you have the kernel headers and build tools installed.
- **Root Privileges**: Root access is required to load/unload kernel modules.
- **Kernel Version Compatibility**: The module is designed for modern Linux kernels (adjust as necessary for your kernel version).
---

## Installation

1. **Clone the repository**:
   ```
   git clone https://github.com/rainsfal1/kernel-eyeing.git
   cd kernel-eyeing
   ```

2. **Build the module**:
   ```
   make
   ```

3. **Insert the module**:
   ```
   sudo insmod interceptor.ko
   ```

4. **Verify the module is loaded**:
   ```
   lsmod | grep interceptor
   ```

5. **Check kernel logs** (for debug and status messages):
   ```
   dmesg
   ```

## Running Tests

You can run the provided test programs to validate the interceptor functionality.

1. **Compile the test files**:
   - For `test_intercept.c`:
     ```
     gcc -o test_intercept test_intercept.c
     ```
   - For `test_full.c`:
     ```
     gcc -o test_full test_full.c
     ```

2. **Run the tests** (root privileges are required):
   - First, run the `test_intercept` test:
     ```
     sudo ./test_intercept
     ```
   - Then, run the `test_full` test:
     ```
     sudo ./test_full
     ```

3. **Check the kernel logs again for any additional messages**:
   ```
   dmesg
   ```
---
## Usage

### Custom System Call
This module defines a custom system call that allows for four commands:

- `REQUEST_SYSCALL_INTERCEPT`: Intercept the specified syscall.
- `REQUEST_SYSCALL_RELEASE`: De-intercept the specified syscall.
- `REQUEST_START_MONITORING`: Start monitoring the specified PID for the intercepted syscall.
- `REQUEST_STOP_MONITORING`: Stop monitoring the specified PID for the intercepted syscall.

### Example
To intercept a system call and start monitoring all PIDs:
1. Intercept a system call (e.g., syscall number 60 for `exit`):
   ```c
   syscall(MY_CUSTOM_SYSCALL, REQUEST_SYSCALL_INTERCEPT, 60, 0);
   ```

2. Start monitoring all PIDs for the intercepted system call:
   ```c
   syscall(MY_CUSTOM_SYSCALL, REQUEST_START_MONITORING, 60, 0);
   ```

3. To stop monitoring and release the syscall, you can:
   ```c
   syscall(MY_CUSTOM_SYSCALL, REQUEST_STOP_MONITORING, 60, 0);
   syscall(MY_CUSTOM_SYSCALL, REQUEST_SYSCALL_RELEASE, 60, 0);
   ```

## Uninstallation

1. **Remove the module**:
   ```
   sudo rmmod interceptor
   ```

2. **Clean the build artifacts**:
   ```
   make clean
   ```

## Development

- **`spin_lock_t` usage**: The module uses spinlocks to ensure synchronization when modifying the system call table and the metadata table.
- **Logging**: Kernel logs (`printk`) provide status updates for debugging and operational logging.
- **Handling process exits**: The module intercepts the `exit_group` syscall to ensure processes are removed from the monitored list upon exit.

## License
This project is licensed under the GNU General Public License (GPL).

---

Feel free to adjust and add any project-specific details that might be necessary.
