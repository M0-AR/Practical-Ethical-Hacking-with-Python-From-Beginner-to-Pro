# Native Code Analysis in Android

## Introduction
Native code analysis involves examining and understanding the compiled C/C++ components of Android applications. This guide covers both basic and advanced techniques for analyzing native libraries (.so files) in Android apps.

## Key Terminology

### Basic Concepts

#### Native Code
- **Definition**: Code written in C/C++ that runs directly on the processor
- **Purpose**: Performance-critical operations, legacy code integration, code protection
- **File Extension**: .so (Shared Object) files

#### JNI (Java Native Interface)
- **Definition**: Framework for Java code to call native functions
- **Components**:
  - Native method declarations
  - JNI function implementations
  - Native library loading
- **Example**:
```java
// Java declaration
native String stringFromJNI();

// Loading library
static {
    System.loadLibrary("native-lib");
}
```

### Analysis Tools

#### 1. IDA Pro
- **Definition**: Professional disassembler and debugger
- **Features**:
  - Interactive disassembly
  - Cross-references
  - Debugging capabilities
- **Usage**: Primary tool for deep native analysis

#### 2. Ghidra
- **Definition**: Open-source software reverse engineering tool
- **Features**:
  - Decompilation
  - Function analysis
  - Script development
- **Advantage**: Free alternative to IDA Pro

#### 3. radare2
- **Definition**: Open-source reverse engineering framework
- **Features**:
  - Command-line interface
  - Binary analysis
  - Debugging capabilities
- **Usage**: Advanced analysis and automation

## Analysis Techniques

### 1. Static Analysis
#### Binary Analysis
- **Definition**: Examining compiled code without execution
- **Methods**:
  - Disassembly review
  - String analysis
  - Cross-reference tracking
- **Tools**: IDA Pro, Ghidra

#### Symbol Analysis
- **Definition**: Examining exported/imported functions
- **Commands**:
```bash
# View symbols
nm -D libnative-lib.so

# List dynamic dependencies
ldd libnative-lib.so
```

### 2. Dynamic Analysis
#### Runtime Debugging
- **Definition**: Analyzing code during execution
- **Tools**:
  - gdb/gdbserver
  - IDA Pro debugger
  - LLDB

#### Memory Analysis
- **Definition**: Examining runtime memory
- **Techniques**:
  - Memory dumps
  - Stack analysis
  - Heap inspection

## Advanced Topics

### 1. Anti-Analysis Techniques
#### Anti-Debugging
- **Definition**: Methods to prevent debugging
- **Techniques**:
  - ptrace checks
  - Timing checks
  - Integrity verification

#### Code Obfuscation
- **Definition**: Methods to make code harder to analyze
- **Types**:
  - Control flow obfuscation
  - String encryption
  - Symbol stripping

### 2. Vulnerability Analysis
#### Memory Corruption
- **Definition**: Bugs that can corrupt memory
- **Types**:
  - Buffer overflows
  - Use-after-free
  - Integer overflows

#### Format String Vulnerabilities
- **Definition**: Improper handling of format strings
- **Impact**: Information disclosure, code execution
- **Detection**: Static and dynamic analysis

## Lab Exercises

### Exercise 1: Basic Native Analysis
1. Extract native libraries
2. Identify exported functions
3. Analyze basic control flow
4. Document findings

### Exercise 2: Advanced Analysis
1. Debug native code
2. Trace function calls
3. Analyze memory usage
4. Identify vulnerabilities

## Documentation Template
```markdown
# Native Code Analysis Report

## Binary Information
- Name:
- Architecture:
- Exported Functions:
- Dependencies:

## Security Analysis
### Protections
- [ ] Symbol stripping
- [ ] Anti-debugging
- [ ] Obfuscation

### Vulnerabilities
1. Issue:
   - Location:
   - Severity:
   - Exploitation:

## Recommendations
1. Security Improvements
2. Implementation Changes
3. Best Practices
```

## Best Practices
1. Always work in isolated environment
2. Document all findings
3. Use multiple analysis tools
4. Verify findings through different methods

## Tools Reference
1. **IDA Pro**
   - Purpose: Professional disassembler
   - Usage: Deep analysis
   - Cost: Commercial

2. **Ghidra**
   - Purpose: Reverse engineering
   - Usage: Code analysis
   - Cost: Free

3. **radare2**
   - Purpose: Framework
   - Usage: Advanced analysis
   - Cost: Free

## Resources
1. Android NDK Documentation
2. Reverse Engineering Books
3. Security Research Papers
4. Tool Documentation
