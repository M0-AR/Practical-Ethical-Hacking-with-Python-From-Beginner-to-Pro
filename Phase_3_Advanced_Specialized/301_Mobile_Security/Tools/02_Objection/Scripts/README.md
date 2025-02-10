# Objection Scripts Guide

## Introduction
Objection scripts are powerful tools for runtime mobile application manipulation. This guide covers both basic and advanced scripting techniques using Objection and Frida.

## Key Terminology

### Basic Concepts

#### Frida Scripts
- **Definition**: JavaScript code for runtime manipulation
- **Purpose**: 
  - Function hooking
  - Memory modification
  - Runtime analysis
- **Usage**: Injected into running processes

#### Runtime Hooking
- **Definition**: Intercepting function calls
- **Components**:
  - Function identification
  - Implementation replacement
  - Call monitoring
- **Example**:
```javascript
// Basic hook example
Java.perform(function() {
    var MainActivity = Java.use("com.example.app.MainActivity");
    MainActivity.isSecure.implementation = function() {
        console.log("[*] Security check bypassed");
        return false;
    };
});
```

### Script Components

#### 1. Method Hooks
- **Definition**: Function interception points
- **Types**:
```javascript
// Method hook types
// 1. Instance method
className.methodName.implementation = function() {};

// 2. Constructor
className.$init.implementation = function() {};

// 3. Overloaded method
className.methodName.overload('int', 'java.lang.String').implementation = function() {};
```

#### 2. Memory Operations
- **Definition**: Memory manipulation functions
- **Features**:
  - Read/Write memory
  - Pattern scanning
  - Memory dumping
- **Example**:
```javascript
// Memory operations
Memory.scan(baseAddr, size, pattern, {
    onMatch: function(address, size) {
        console.log('[+] Pattern found at:', address);
    }
});
```

## Script Categories

### 1. Security Bypass Scripts
#### Root Detection Bypass
- **Definition**: Circumventing root checks
- **Implementation**:
```javascript
// Root detection bypass
Java.perform(function() {
    var RootCheck = Java.use("com.app.security.RootCheck");
    RootCheck.isRooted.implementation = function() {
        console.log("[*] Root check bypassed");
        return false;
    };
});
```

#### SSL Pinning Bypass
- **Definition**: Certificate validation bypass
- **Code**:
```javascript
// SSL pinning bypass
Java.perform(function() {
    var TrustManager = Java.use('javax.net.ssl.X509TrustManager');
    var SSLContext = Java.use('javax.net.ssl.SSLContext');
    
    // Implement custom TrustManager
    var TrustManager = Java.registerClass({
        name: 'com.custom.TrustManager',
        implements: [TrustManager],
        methods: {
            checkClientTrusted: function(chain, authType) {},
            checkServerTrusted: function(chain, authType) {},
            getAcceptedIssuers: function() { return []; }
        }
    });
});
```

### 2. Analysis Scripts
#### API Monitoring
- **Definition**: Tracking API calls
- **Example**:
```javascript
// API monitoring
Java.perform(function() {
    var HttpURLConnection = Java.use("java.net.HttpURLConnection");
    HttpURLConnection.connect.implementation = function() {
        console.log("[*] HTTP Connection:", this.getURL());
        return this.connect();
    };
});
```

#### Data Extraction
- **Definition**: Retrieving runtime data
- **Implementation**:
```javascript
// Data extraction
Java.perform(function() {
    var SharedPrefs = Java.use("android.content.SharedPreferences");
    SharedPrefs.getString.implementation = function(key, defValue) {
        var value = this.getString(key, defValue);
        console.log("[*] SharedPrefs:", key, "=", value);
        return value;
    };
});
```

## Advanced Features

### 1. Custom Hooks
#### Native Library Hooks
- **Definition**: Hooking native functions
- **Example**:
```javascript
// Native hook
Interceptor.attach(Module.findExportByName(null, "strcmp"), {
    onEnter: function(args) {
        this.arg0 = args[0];
        this.arg1 = args[1];
    },
    onLeave: function(retval) {
        console.log("[*] strcmp:", 
            Memory.readUtf8String(this.arg0),
            Memory.readUtf8String(this.arg1)
        );
    }
});
```

#### Dynamic Instrumentation
- **Definition**: Runtime code modification
- **Features**:
  - Function replacement
  - Return value modification
  - Parameter manipulation

### 2. Advanced Analysis
#### Memory Pattern Scanning
- **Definition**: Searching memory patterns
- **Implementation**:
```javascript
// Memory scanning
Memory.scan(ptr('0x1000'), 1024, '00 01 02 03', {
    onMatch: function(address, size) {
        console.log('[+] Pattern found at:', address);
    },
    onError: function(reason) {
        console.log('[!] Error:', reason);
    },
    onComplete: function() {
        console.log('[*] Scan complete');
    }
});
```

## Lab Exercises

### Exercise 1: Basic Scripting
1. **Method Hooking**
   - Definition: Creating basic hooks
   - Steps:
     ```javascript
     // Basic hook exercise
     Java.perform(function() {
         var target = Java.use("com.example.Target");
         target.method.implementation = function() {
             console.log("[*] Method called");
             return this.method();
         };
     });
     ```

2. **Data Monitoring**
   - Definition: Tracking data flow
   - Implementation:
     - Hook getters/setters
     - Monitor variables
     - Log operations

### Exercise 2: Advanced Scripting
1. **Native Code Analysis**
   - Definition: Analyzing native libraries
   - Process:
     - Function identification
     - Hook implementation
     - Data extraction

2. **Custom Instrumentation**
   - Definition: Creating custom tools
   - Features:
     - Specialized hooks
     - Data processors
     - Analysis tools

## Documentation Template
```markdown
# Script Documentation

## Purpose
- Target:
- Functionality:
- Requirements:

## Implementation
### Hooks
1. Method:
   - Target:
   - Modification:
   - Output:

### Analysis
1. Feature:
   - Description:
   - Data:
   - Results:
```

## Best Practices

### 1. Script Development
#### Code Organization
- **Definition**: Structuring scripts
- **Guidelines**:
  - Modular design
  - Clear comments
  - Error handling

#### Performance
- **Definition**: Optimization techniques
- **Methods**:
  - Efficient hooks
  - Memory management
  - Resource cleanup

### 2. Testing
#### Script Validation
- **Definition**: Verifying functionality
- **Process**:
  - Test cases
  - Error scenarios
  - Performance checks

#### Debugging
- **Definition**: Troubleshooting issues
- **Tools**:
  - Console logging
  - Error tracking
  - State monitoring

## Troubleshooting

### Common Issues
1. **Hook Failures**
   - Definition: Failed function hooks
   - Solutions:
     - Method verification
     - Class checking
     - Error handling

2. **Memory Issues**
   - Definition: Memory-related problems
   - Solutions:
     - Resource cleanup
     - Memory limits
     - Leak prevention

## Resources
1. Frida Documentation
2. Objection Wiki
3. Sample Scripts
4. Community Forums

## Next Steps
1. Practice basic hooks
2. Study advanced patterns
3. Create custom tools
4. Share with community
