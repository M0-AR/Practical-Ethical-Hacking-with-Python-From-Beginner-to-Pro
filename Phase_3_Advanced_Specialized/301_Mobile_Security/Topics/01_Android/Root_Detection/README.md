# Android Root Detection and Bypass Techniques

## Introduction to Root Detection

Root detection is a security measure implemented in Android applications to identify if a device has been rooted. This guide covers both implementation and bypass techniques.

## Basic Concepts

### 1. What is Root?
Root access provides privileged control (superuser access) over the Android operating system. This includes:
- Full access to system files
- Ability to modify system settings
- Permission to execute privileged commands
- Access to protected application data

### 2. Why Detect Root?
Applications check for root access to:
- Protect sensitive data
- Prevent unauthorized modifications
- Maintain application integrity
- Comply with security requirements

## Root Detection Methods

### 1. File-Based Detection

#### Check for Su Binary
```java
public class RootDetector {
    private static final String[] SU_PATHS = {
        "/system/bin/su",
        "/system/xbin/su",
        "/sbin/su",
        "/system/app/Superuser.apk",
        "/system/etc/init.d/99SuperSUDaemon",
        "/dev/com.koushikdutta.superuser.daemon/"
    };

    public boolean checkForRootBinaries() {
        for (String path : SU_PATHS) {
            if (new File(path).exists()) {
                return true;
            }
        }
        return false;
    }
}
```

#### Check for Root Management Apps
```java
public boolean checkForRootManagementApps() {
    final String[] rootApps = {
        "com.noshufou.android.su",
        "com.thirdparty.superuser",
        "eu.chainfire.supersu",
        "com.topjohnwu.magisk"
    };

    PackageManager pm = context.getPackageManager();
    for (String appName : rootApps) {
        try {
            pm.getPackageInfo(appName, PackageManager.GET_ACTIVITIES);
            return true;
        } catch (PackageManager.NameNotFoundException e) {
            continue;
        }
    }
    return false;
}
```

### 2. Permission-Based Detection

#### Check for Root Permissions
```java
public boolean checkForRootPermissions() {
    Process process = null;
    try {
        process = Runtime.getRuntime().exec(new String[] {"which", "su"});
        BufferedReader in = new BufferedReader(new InputStreamReader(process.getInputStream()));
        return in.readLine() != null;
    } catch (IOException e) {
        return false;
    } finally {
        if (process != null) {
            process.destroy();
        }
    }
}
```

#### Check Write Permissions
```java
public boolean checkSystemWritePermissions() {
    String[] paths = {"/system", "/system/bin", "/system/sbin", "/system/xbin"};
    
    for (String path : paths) {
        File file = new File(path);
        if (file.canWrite()) {
            return true;
        }
    }
    return false;
}
```

### 3. Property-Based Detection

#### Check System Properties
```java
public boolean checkForDangerousProps() {
    final String[] dangerousProps = {
        "ro.debuggable",
        "ro.secure",
        "ro.build.selinux",
        "ro.build.tags"
    };

    try {
        for (String prop : dangerousProps) {
            String value = System.getProperty(prop);
            if (value != null && value.contains("test-keys")) {
                return true;
            }
        }
    } catch (Exception e) {
        e.printStackTrace();
    }
    return false;
}
```

### 4. Advanced Detection Methods

#### Native Library Checks
```java
public class NativeRootChecker {
    static {
        System.loadLibrary("rootchecker");
    }

    public native boolean checkForRoot();
}

// In C/C++
JNIEXPORT jboolean JNICALL
Java_com_example_app_NativeRootChecker_checkForRoot(JNIEnv *env, jobject thiz) {
    if (access("/system/bin/su", F_OK) == 0) {
        return JNI_TRUE;
    }
    return JNI_FALSE;
}
```

#### Runtime Integrity Checks
```java
public boolean checkRuntimeIntegrity() {
    try {
        throw new Exception("Stack trace");
    } catch (Exception e) {
        int zygoteInitCallCount = 0;
        for (StackTraceElement stack : e.getStackTrace()) {
            if (stack.getClassName().equals("com.android.internal.os.ZygoteInit")) {
                zygoteInitCallCount++;
                if (zygoteInitCallCount > 1) {
                    return false; // Multiple Zygote calls indicate tampering
                }
            }
        }
    }
    return true;
}
```

## Root Detection Bypass Techniques

### 1. Hooking Methods

#### Frida Hook Example
```javascript
Java.perform(function() {
    // Hook basic root checks
    var RootDetector = Java.use("com.example.app.RootDetector");
    
    RootDetector.checkForRootBinaries.implementation = function() {
        console.log("[*] Root binary check bypassed");
        return false;
    };
    
    RootDetector.checkForRootManagementApps.implementation = function() {
        console.log("[*] Root management apps check bypassed");
        return false;
    };
    
    // Hook native checks
    var NativeRootChecker = Java.use("com.example.app.NativeRootChecker");
    NativeRootChecker.checkForRoot.implementation = function() {
        console.log("[*] Native root check bypassed");
        return false;
    };
});
```

#### Xposed Module Example
```java
public class RootCloakModule implements IXposedHookLoadPackage {
    @Override
    public void handleLoadPackage(LoadPackageParam lpparam) throws Throwable {
        if (!lpparam.packageName.equals("com.example.app")) return;

        XposedHelpers.findAndHookMethod("com.example.app.RootDetector",
            lpparam.classLoader,
            "checkForRootBinaries",
            new XC_MethodReplacement() {
                @Override
                protected Object replaceHookedMethod(MethodHookParam param) throws Throwable {
                    XposedBridge.log("Root binary check bypassed");
                    return false;
                }
            });
    }
}
```

### 2. File System Manipulation

#### Hide Root Files
```bash
# Rename su binary
mv /system/bin/su /system/bin/su_backup

# Create fake non-executable su
touch /system/bin/su
chmod 000 /system/bin/su
```

#### Mount Namespace Modification
```c
// Create separate mount namespace
#define _GNU_SOURCE
#include <sched.h>

int main() {
    if (unshare(CLONE_NEWNS) == -1) {
        perror("unshare failed");
        return 1;
    }
    
    // Mount empty tmpfs over sensitive directories
    if (mount("tmpfs", "/system/bin", "tmpfs", 0, NULL) == -1) {
        perror("mount failed");
        return 1;
    }
    
    return 0;
}
```

### 3. System Property Manipulation

#### Build.prop Modification
```bash
# Backup original
cp /system/build.prop /system/build.prop.bak

# Modify properties
sed -i 's/ro.build.tags=test-keys/ro.build.tags=release-keys/g' /system/build.prop
sed -i 's/ro.debuggable=1/ro.debuggable=0/g' /system/build.prop
```

#### Runtime Property Override
```java
// Hook property access
Java.perform(function() {
    var SystemProperties = Java.use("android.os.SystemProperties");
    
    SystemProperties.get.overload('java.lang.String').implementation = function(key) {
        if (key === "ro.build.tags") {
            return "release-keys";
        }
        return this.get(key);
    };
});
```

## Advanced Root Detection Implementation

### 1. Multi-Layer Detection
```java
public class AdvancedRootDetector {
    private final Context context;
    private final List<RootDetectionMethod> detectionMethods;
    
    public AdvancedRootDetector(Context context) {
        this.context = context;
        this.detectionMethods = new ArrayList<>();
        initializeDetectionMethods();
    }
    
    private void initializeDetectionMethods() {
        detectionMethods.add(new BinaryDetection());
        detectionMethods.add(new PackageDetection());
        detectionMethods.add(new PropertyDetection());
        detectionMethods.add(new PermissionDetection());
        detectionMethods.add(new NativeDetection());
    }
    
    public boolean isDeviceRooted() {
        int detectionCount = 0;
        for (RootDetectionMethod method : detectionMethods) {
            if (method.detect(context)) {
                detectionCount++;
                if (detectionCount >= 2) {  // Require multiple detections
                    return true;
                }
            }
        }
        return false;
    }
}

interface RootDetectionMethod {
    boolean detect(Context context);
}
```

### 2. Time-Based Detection
```java
public class TimeBasedRootDetector {
    private static final int CHECK_INTERVAL = 5000; // 5 seconds
    private boolean previousResult = false;
    private long lastCheckTime = 0;
    
    public boolean isRooted() {
        long currentTime = System.currentTimeMillis();
        if (currentTime - lastCheckTime > CHECK_INTERVAL) {
            boolean currentResult = performRootChecks();
            if (currentResult != previousResult) {
                // Root status changed, possible tampering
                logPossibleTampering();
            }
            previousResult = currentResult;
            lastCheckTime = currentTime;
        }
        return previousResult;
    }
    
    private void logPossibleTampering() {
        // Implement secure logging
        SecurityLogger.log("Root status changed - possible tampering detected");
    }
}
```

## Documentation Template
```markdown
# Root Detection Analysis Report

## Application Details
- Package Name:
- Version:
- Detection Methods Used:

## Detection Results
### File-Based Checks
- [ ] Su binary present
- [ ] Root management apps found
- [ ] Suspicious files detected

### Permission Checks
- [ ] Root permissions detected
- [ ] System write access found
- [ ] Dangerous permissions present

### Property Checks
- [ ] Build properties modified
- [ ] System properties altered
- [ ] Security settings changed

## Bypass Analysis
### Attempted Methods
1. Method:
   - Success:
   - Detection:
   - Countermeasures:

### Recommendations
1. Implementation:
   - Current:
   - Suggested:
   - Priority:
```

## Best Practices

### 1. Implementation Guidelines
- Use multiple detection methods
- Implement native checks
- Add time-based verification
- Include integrity checking
- Implement secure logging

### 2. Anti-Tampering Measures
- Obfuscate detection code
- Use native implementations
- Implement integrity checks
- Add time-based verification
- Monitor for hooking attempts

## Troubleshooting Guide

### Common Issues
1. False Positives
   - Custom ROM detection
   - Developer options enabled
   - Debug builds

2. Bypass Detection
   - Hook detection
   - File system manipulation
   - Property modification

## Resources
1. Android Security Documentation
2. Root Detection Libraries
3. Anti-Root Bypass Tools
4. Security Communities
