# Decompilation Analysis

## Introduction
This section focuses on decompiling Android applications to analyze their source code, understand their behavior, and identify potential security issues.

## Learning Objectives
1. Master APK decompilation techniques
2. Understand different decompiler tools
3. Analyze Java/Kotlin source code
4. Identify security vulnerabilities

## Decompilation Tools

### 1. dex2jar
- **Purpose**: Convert DEX to JAR
- **Usage**:
```bash
# Convert DEX to JAR
d2j-dex2jar classes.dex

# Handle multiple DEX files
d2j-dex2jar classes*.dex
```
- **Common Issues**:
  - Version compatibility
  - Obfuscated code
  - Multiple DEX files

### 2. JD-GUI
- **Purpose**: Java decompiler
- **Features**:
  - Source code viewing
  - Class navigation
  - Code export
- **Best Practices**:
  - Save all sources
  - Check for errors
  - Handle dependencies

### 3. JADX
- **Purpose**: Android decompiler
- **Advantages**:
  - Better handling of Kotlin
  - Resource viewing
  - Search capabilities
- **Usage**:
```bash
jadx-gui application.apk
```

## Analysis Techniques

### 1. Source Code Analysis
- **Entry Points**
  - Main Activity
  - Services
  - Receivers
  - Custom Application class

- **Security-Critical Code**
  - Authentication
  - Encryption
  - Network calls
  - Data storage

- **Anti-Analysis Checks**
  - Root detection
  - Emulator detection
  - Debugger detection

### 2. Control Flow Analysis
- **Method Tracing**
  - Entry points
  - Call hierarchy
  - Data flow

- **Critical Paths**
  - Authentication flows
  - Payment processes
  - Sensitive operations

### 3. Resource Analysis
- **String Resources**
  - Hardcoded credentials
  - API endpoints
  - Configuration data

- **Binary Resources**
  - Embedded certificates
  - Encryption keys
  - Custom formats

## Common Vulnerabilities

### 1. Insecure Data Storage
- **What to Look For**:
  - Plaintext credentials
  - Hardcoded keys
  - Sensitive data in preferences

- **Code Patterns**:
```java
// Insecure storage examples
SharedPreferences.Editor editor = prefs.edit();
editor.putString("password", plainTextPassword);

// File operations
FileOutputStream fos = openFileOutput("sensitive.txt", Context.MODE_PRIVATE);
```

### 2. Weak Cryptography
- **Common Issues**:
  - Weak algorithms
  - Hardcoded keys
  - Predictable IVs

- **Code Patterns**:
```java
// Weak encryption examples
Cipher cipher = Cipher.getInstance("DES");
String hardcodedKey = "1234567890abcdef";
```

### 3. Insecure Communication
- **Network Calls**:
  - HTTP usage
  - Invalid SSL validation
  - Missing certificate pinning

- **Code Patterns**:
```java
// Insecure network examples
URL url = new URL("http://api.example.com");
trustAllCertificates();
```

## Advanced Topics

### 1. Native Code Analysis
- **JNI Functions**
  - Native method declarations
  - JNI implementations
  - Native libraries

- **Tools**:
  - IDA Pro
  - Ghidra
  - radare2

### 2. Obfuscation Analysis
- **Common Techniques**:
  - Name obfuscation
  - Control flow obfuscation
  - String encryption

- **Deobfuscation**:
  - Manual analysis
  - Automated tools
  - Pattern matching

## Documentation Template
```markdown
# Decompilation Analysis Report

## Application Information
- Name:
- Version:
- Package:
- Decompiler Used:

## Code Analysis
### Entry Points
- Main Activity:
- Services:
- Receivers:

### Security Features
1. Authentication
2. Encryption
3. Network Security

### Vulnerabilities
1. Issue:
   - Location:
   - Severity:
   - Mitigation:

## Recommendations
1. Security Improvements
2. Code Quality
3. Best Practices
```

## Next Steps
1. Practice with real applications
2. Learn advanced deobfuscation
3. Study native code analysis
4. Explore automation tools

## Resources
1. Android Developer Documentation
2. OWASP Mobile Security Testing Guide
3. Decompiler Documentation
4. Security Research Papers
