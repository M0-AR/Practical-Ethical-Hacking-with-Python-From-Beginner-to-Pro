# Frida Hooking in Android

## Introduction to Frida

Frida is a dynamic instrumentation toolkit that allows you to inject JavaScript into native applications. In Android security testing, it's used to hook into running processes, modify their behavior, and analyze their functionality.

## Basic Concepts

### 1. Process Injection

#### How Frida Works
Frida injects its JavaScript runtime into a target process, allowing real-time manipulation of the application.

```javascript
// Basic process attachment
Java.perform(function() {
    console.log("[*] Starting Frida hook");
});
```

#### Process Selection
```javascript
// List running processes
frida-ps -U

// Attach to specific process
frida -U -f com.example.app
```

### 2. Java Layer Hooking

#### Class Hooking
```javascript
Java.perform(function() {
    // Find and hook a class
    var MainActivity = Java.use("com.example.app.MainActivity");
    
    // Hook specific method
    MainActivity.onCreate.implementation = function(savedInstanceState) {
        console.log("[*] onCreate called");
        
        // Call original implementation
        this.onCreate(savedInstanceState);
        
        console.log("[*] onCreate completed");
    };
});
```

#### Method Overloading
```javascript
Java.perform(function() {
    var target = Java.use("com.example.app.SecurityManager");
    
    // Hook specific overload
    target.checkPassword.overload('java.lang.String').implementation = function(password) {
        console.log("[*] Password check called with:", password);
        return true;  // Bypass password check
    };
    
    // Hook all overloads
    target.checkPassword.overloads.forEach(function(overload) {
        overload.implementation = function() {
            console.log("[*] Password check called with args:", arguments);
            return true;
        };
    });
});
```

## Advanced Hooking Techniques

### 1. Native Layer Hooking

#### Library Functions
```javascript
// Hook native library function
Interceptor.attach(Module.findExportByName("libnative.so", "Java_com_example_app_NativeLib_check"), {
    onEnter: function(args) {
        console.log("[*] Native check called");
        this.context = args[0];  // Save context for onLeave
    },
    onLeave: function(retval) {
        console.log("[*] Native check returning:", retval);
        retval.replace(1);  // Modify return value
    }
});
```

#### Memory Operations
```javascript
// Memory manipulation
Memory.scan(ptr('0x1000'), 1024, "DE AD BE EF", {
    onMatch: function(address, size) {
        console.log('[+] Pattern found at:', address);
        // Read memory
        console.log(hexdump(address, {
            offset: 0,
            length: 64,
            header: true,
            ansi: true
        }));
    },
    onError: function(reason) {
        console.log('[!] Memory scan failed:', reason);
    },
    onComplete: function() {
        console.log('[*] Memory scan completed');
    }
});
```

### 2. Runtime Manipulation

#### Class Loading
```javascript
Java.perform(function() {
    // Enumerate loaded classes
    Java.enumerateLoadedClasses({
        onMatch: function(className) {
            if (className.includes("example")) {
                console.log("[+] Found target class:", className);
            }
        },
        onComplete: function() {
            console.log("[*] Class enumeration completed");
        }
    });
    
    // Create new class instance
    var SecurityBypass = Java.use("com.example.app.SecurityManager");
    var instance = SecurityBypass.$new();
});
```

#### Method Tracing
```javascript
Java.perform(function() {
    var target = Java.use("com.example.app.CryptoManager");
    
    // Trace all crypto operations
    target.$init.implementation = function() {
        console.log("[*] CryptoManager initialized");
        console.log("[*] Backtrace:\n" +
            Thread.backtrace(this.context, Backtracer.ACCURATE)
            .map(DebugSymbol.fromAddress).join("\n"));
        return this.$init();
    };
});
```

## Security Bypass Examples

### 1. Root Detection Bypass
```javascript
Java.perform(function() {
    // Bypass multiple root detection methods
    var RootCheck = Java.use("com.example.app.RootDetection");
    
    // Method 1: File check bypass
    RootCheck.checkForSUBinary.implementation = function() {
        console.log("[*] Root binary check bypassed");
        return false;
    };
    
    // Method 2: Package check bypass
    RootCheck.checkForRootManagementApps.implementation = function() {
        console.log("[*] Root management check bypassed");
        return false;
    };
    
    // Method 3: Property check bypass
    RootCheck.checkForRootNativeProperties.implementation = function() {
        console.log("[*] Root properties check bypassed");
        return false;
    };
});
```

### 2. SSL Pinning Bypass
```javascript
Java.perform(function() {
    // Bypass certificate validation
    var TrustManager = Java.use('javax.net.ssl.X509TrustManager');
    var SSLContext = Java.use('javax.net.ssl.SSLContext');
    
    // Create custom trust manager
    var TrustManagerImpl = Java.registerClass({
        name: 'com.example.SSLBypass',
        implements: [TrustManager],
        methods: {
            checkClientTrusted: function(chain, authType) {},
            checkServerTrusted: function(chain, authType) {},
            getAcceptedIssuers: function() { return []; }
        }
    });
    
    // Replace SSL context
    var TrustManagers = [TrustManagerImpl.$new()];
    var SSLContextImpl = SSLContext.getInstance('TLS');
    SSLContextImpl.init(null, TrustManagers, null);
    
    var SSLSocketFactory = SSLContextImpl.getSocketFactory();
});
```

## Advanced Analysis Techniques

### 1. API Monitoring
```javascript
Java.perform(function() {
    // Monitor HTTP requests
    var OkHttpClient = Java.use("okhttp3.OkHttpClient");
    var Request = Java.use("okhttp3.Request");
    
    OkHttpClient.newCall.implementation = function(request) {
        var url = request.url().toString();
        console.log("[*] HTTP Request:", url);
        
        // Log headers
        var headers = request.headers();
        for (var i = 0; i < headers.size(); i++) {
            console.log("\tHeader:", headers.name(i), "=", headers.value(i));
        }
        
        return this.newCall(request);
    };
});
```

### 2. Data Extraction
```javascript
Java.perform(function() {
    // Monitor database operations
    var SQLiteDatabase = Java.use("android.database.sqlite.SQLiteDatabase");
    
    SQLiteDatabase.rawQuery.overload('java.lang.String', '[Ljava.lang.String;')
    .implementation = function(sql, args) {
        console.log("[*] SQL Query:", sql);
        if (args) {
            console.log("[*] Arguments:", JSON.stringify(args));
        }
        
        var cursor = this.rawQuery(sql, args);
        
        // Extract results
        if (cursor) {
            var rows = [];
            while(cursor.moveToNext()) {
                var row = {};
                for(var i = 0; i < cursor.getColumnCount(); i++) {
                    var columnName = cursor.getColumnName(i);
                    var columnType = cursor.getType(i);
                    var value;
                    
                    switch(columnType) {
                        case 1: // INTEGER
                            value = cursor.getLong(i);
                            break;
                        case 2: // FLOAT
                            value = cursor.getDouble(i);
                            break;
                        case 3: // STRING
                            value = cursor.getString(i);
                            break;
                        case 4: // BLOB
                            value = cursor.getBlob(i);
                            break;
                    }
                    row[columnName] = value;
                }
                rows.push(row);
            }
            console.log("[*] Query results:", JSON.stringify(rows, null, 2));
        }
        
        return cursor;
    };
});
```

## Best Practices

### 1. Script Organization
```javascript
// Modular script structure
var hooks = {
    init: function() {
        Java.perform(function() {
            hooks.hookSecurity();
            hooks.hookNetwork();
            hooks.hookCrypto();
        });
    },
    
    hookSecurity: function() {
        // Security related hooks
    },
    
    hookNetwork: function() {
        // Network related hooks
    },
    
    hookCrypto: function() {
        // Crypto related hooks
    }
};

hooks.init();
```

### 2. Error Handling
```javascript
Java.perform(function() {
    try {
        // Attempt hooks
        var target = Java.use("com.example.app.Target");
        target.method.implementation = function() {
            try {
                // Method hook logic
                return this.method();
            } catch(e) {
                console.error("[!] Error in method hook:", e);
                return this.method();
            }
        };
    } catch(e) {
        console.error("[!] Error setting up hooks:", e);
    }
});
```

## Documentation Template
```markdown
# Frida Hook Analysis

## Target Information
- Application:
- Package Name:
- Target Class:
- Target Method:

## Hook Implementation
### Purpose
- Objective:
- Expected Behavior:
- Modified Behavior:

### Code
```javascript
// Hook implementation
```

### Results
- Original Behavior:
- Modified Behavior:
- Side Effects:

## Security Implications
- Risk Level:
- Impact:
- Mitigation:
```

## Troubleshooting Guide

### Common Issues
1. Process Attachment Failures
   ```bash
   # Check device connection
   adb devices
   
   # Check process status
   frida-ps -U
   
   # Check Frida server
   adb shell ps | grep frida
   ```

2. Hook Failures
   ```javascript
   // Debug hook loading
   Java.perform(function() {
       try {
           var target = Java.use("com.example.app.Target");
           console.log("[+] Class found");
       } catch(e) {
           console.log("[!] Class not found:", e);
       }
   });
   ```

## Resources
1. Frida Documentation
2. Example Scripts
3. Android Security Resources
4. Community Support
