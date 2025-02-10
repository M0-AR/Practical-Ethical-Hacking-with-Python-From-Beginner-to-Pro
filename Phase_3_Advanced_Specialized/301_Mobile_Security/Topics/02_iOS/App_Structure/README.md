# iOS Application Structure

## Introduction
This guide covers the fundamental structure of iOS applications, including their components, security boundaries, and best practices for secure implementation.

## Basic Concepts

### 1. Application Bundle
The iOS app bundle (.app) contains:
- Binary executable
- Resources (images, audio, etc.)
- Info.plist
- Storyboards/NIBs
- Frameworks

#### Bundle Structure
```plaintext
MyApp.app/
├── Info.plist
├── MyApp (binary)
├── Assets.car
├── Base.lproj/
├── Frameworks/
└── _CodeSignature/
```

### 2. Application Sandbox

#### Directory Structure
```swift
// Get application directories
class func getAppDirectories() {
    let fm = FileManager.default
    
    // Documents directory - user data
    if let documentsPath = fm.urls(for: .documentDirectory, in: .userDomainMask).first {
        print("Documents:", documentsPath.path)
    }
    
    // Library directory - non-user data
    if let libraryPath = fm.urls(for: .libraryDirectory, in: .userDomainMask).first {
        print("Library:", libraryPath.path)
    }
    
    // Caches directory - temporary files
    if let cachesPath = fm.urls(for: .cachesDirectory, in: .userDomainMask).first {
        print("Caches:", cachesPath.path)
    }
    
    // Temporary directory
    print("Temp:", NSTemporaryDirectory())
}
```

#### Security Boundaries
```swift
// File protection
class FileProtectionManager {
    static func secureFile(at path: String) throws {
        let fileURL = URL(fileURLWithPath: path)
        try (fileURL as NSURL).setResourceValue(
            URLFileProtection.complete,
            forKey: .fileProtectionKey
        )
    }
    
    static func checkProtection(at path: String) throws -> URLFileProtection {
        let fileURL = URL(fileURLWithPath: path)
        var protection: AnyObject?
        try (fileURL as NSURL).getResourceValue(
            &protection,
            forKey: .fileProtectionKey
        )
        return protection as! URLFileProtection
    }
}
```

## Core Components

### 1. Info.plist Configuration

#### Basic Configuration
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key>
    <string>com.example.app</string>
    <key>CFBundleVersion</key>
    <string>1.0</string>
    <key>LSRequiresIPhoneOS</key>
    <true/>
    <key>UIRequiredDeviceCapabilities</key>
    <array>
        <string>armv7</string>
    </array>
    <key>UISupportedInterfaceOrientations</key>
    <array>
        <string>UIInterfaceOrientationPortrait</string>
    </array>
</dict>
</plist>
```

#### Security Configurations
```xml
<!-- App Transport Security -->
<key>NSAppTransportSecurity</key>
<dict>
    <key>NSAllowsArbitraryLoads</key>
    <false/>
    <key>NSExceptionDomains</key>
    <dict>
        <key>example.com</key>
        <dict>
            <key>NSExceptionAllowsInsecureHTTPLoads</key>
            <false/>
            <key>NSExceptionRequiresForwardSecrecy</key>
            <true/>
            <key>NSExceptionMinimumTLSVersion</key>
            <string>TLSv1.2</string>
        </dict>
    </dict>
</dict>

<!-- Privacy Permissions -->
<key>NSCameraUsageDescription</key>
<string>Camera access for scanning documents</string>
<key>NSPhotoLibraryUsageDescription</key>
<string>Photo access for uploading documents</string>
```

### 2. Application Delegate

#### Basic Implementation
```swift
@UIApplicationMain
class AppDelegate: UIResponder, UIApplicationDelegate {
    var window: UIWindow?
    
    func application(_ application: UIApplication,
                    didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {
        // Initialize security components
        setupSecurity()
        
        // Configure root view controller
        window = UIWindow(frame: UIScreen.main.bounds)
        window?.rootViewController = RootViewController()
        window?.makeKeyAndVisible()
        
        return true
    }
    
    private func setupSecurity() {
        // Configure app security settings
        configureJailbreakDetection()
        configureSSLPinning()
        configureDataProtection()
    }
}
```

#### Security Lifecycle Methods
```swift
extension AppDelegate {
    func applicationWillResignActive(_ application: UIApplication) {
        // Protect sensitive UI
        window?.secureScreen()
    }
    
    func applicationDidEnterBackground(_ application: UIApplication) {
        // Secure data
        DataProtectionManager.shared.lockSensitiveData()
    }
    
    func applicationWillEnterForeground(_ application: UIApplication) {
        // Verify app integrity
        guard SecurityManager.shared.verifyIntegrity() else {
            handleSecurityViolation()
            return
        }
    }
    
    func applicationDidBecomeActive(_ application: UIApplication) {
        // Reset security state
        window?.removeSecureScreen()
    }
}
```

## Advanced Features

### 1. Data Protection

#### Keychain Integration
```swift
class KeychainManager {
    static func saveSecureItem(_ item: String, forKey key: String) -> OSStatus {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecValueData as String: item.data(using: .utf8)!,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        ]
        
        SecItemDelete(query as CFDictionary)
        return SecItemAdd(query as CFDictionary, nil)
    }
    
    static func loadSecureItem(forKey key: String) -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecReturnData as String: kCFBooleanTrue!,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        
        var dataTypeRef: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &dataTypeRef)
        
        if status == errSecSuccess {
            if let data = dataTypeRef as? Data,
               let result = String(data: data, encoding: .utf8) {
                return result
            }
        }
        return nil
    }
}
```

#### File Data Protection
```swift
class DataProtectionManager {
    static func protectFile(at path: String, withKey key: String) throws {
        // Generate encryption key
        let keyData = try generateEncryptionKey(withPassword: key)
        
        // Read file data
        let fileData = try Data(contentsOf: URL(fileURLWithPath: path))
        
        // Encrypt data
        let encryptedData = try encryptData(fileData, withKey: keyData)
        
        // Save encrypted data
        try encryptedData.write(to: URL(fileURLWithPath: path))
    }
    
    private static func generateEncryptionKey(withPassword password: String) throws -> Data {
        let salt = try generateRandomBytes(length: 32)
        var key = Data(count: 32)
        
        let result = key.withUnsafeMutableBytes { keyPtr in
            salt.withUnsafeBytes { saltPtr in
                CCKeyDerivationPBKDF(
                    CCPBKDFAlgorithm(kCCPBKDF2),
                    password, password.count,
                    saltPtr.baseAddress!, salt.count,
                    CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                    10000,
                    keyPtr.baseAddress!, key.count
                )
            }
        }
        
        guard result == kCCSuccess else {
            throw Error.keyGenerationFailed
        }
        
        return key
    }
}
```

### 2. URL Scheme Handling

#### URL Scheme Registration
```xml
<!-- Info.plist -->
<key>CFBundleURLTypes</key>
<array>
    <dict>
        <key>CFBundleURLSchemes</key>
        <array>
            <string>myapp</string>
        </array>
        <key>CFBundleURLName</key>
        <string>com.example.app</string>
    </dict>
</array>
```

#### Secure URL Handling
```swift
class URLSchemeHandler {
    static func handleURL(_ url: URL) -> Bool {
        // Validate URL scheme
        guard url.scheme == "myapp" else {
            return false
        }
        
        // Validate host
        guard let host = url.host else {
            return false
        }
        
        // Parse and validate parameters
        let components = URLComponents(url: url, resolvingAgainstBaseURL: true)
        guard let params = components?.queryItems else {
            return false
        }
        
        // Handle different actions
        switch host {
        case "login":
            return handleLogin(params)
        case "payment":
            return handlePayment(params)
        default:
            return false
        }
    }
    
    private static func handleLogin(_ params: [URLQueryItem]) -> Bool {
        // Validate required parameters
        guard let token = params.first(where: { $0.name == "token" })?.value,
              validateToken(token) else {
            return false
        }
        
        // Process login
        return processLogin(withToken: token)
    }
}
```

## Security Best Practices

### 1. Code Signing

#### Entitlements Configuration
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.developer.default-data-protection</key>
    <string>NSFileProtectionComplete</string>
    <key>com.apple.security.application-groups</key>
    <array>
        <string>group.com.example.app</string>
    </array>
    <key>keychain-access-groups</key>
    <array>
        <string>$(AppIdentifierPrefix)com.example.app</string>
    </array>
</dict>
</plist>
```

#### Code Signing Verification
```swift
class CodeSigningVerifier {
    static func verifyCodeSigning() -> Bool {
        #if DEBUG
        return true
        #else
        var staticCode: SecStaticCode?
        var requirement: SecRequirement?
        
        // Get static code
        guard SecStaticCodeCreateWithPath(
            Bundle.main.bundleURL as CFURL,
            [], &staticCode
        ) == errSecSuccess else {
            return false
        }
        
        // Create requirement
        guard SecRequirementCreateWithString(
            """
            anchor apple generic and certificate leaf[subject.CN] = \
            "iPhone Developer: Developer Name (XXXXXXXXXX)"
            """ as CFString,
            [], &requirement
        ) == errSecSuccess else {
            return false
        }
        
        // Verify signature
        return SecStaticCodeCheckValidityWithErrors(
            staticCode!,
            SecCSFlags(rawValue: 0),
            requirement,
            nil
        ) == errSecSuccess
        #endif
    }
}
```

### 2. Memory Protection

#### Secure Memory Management
```swift
class SecureString {
    private var data: UnsafeMutableBufferPointer<UInt8>
    
    init(_ string: String) {
        let stringData = string.data(using: .utf8)!
        data = UnsafeMutableBufferPointer<UInt8>.allocate(capacity: stringData.count)
        _ = stringData.copyBytes(to: data)
    }
    
    deinit {
        // Securely clear memory
        for i in 0..<data.count {
            data[i] = 0
        }
        data.deallocate()
    }
    
    func access<T>(_ block: (String) -> T) -> T {
        let string = String(data: Data(buffer: data), encoding: .utf8)!
        defer {
            // Clear stack variables
            autoreleasepool { }
        }
        return block(string)
    }
}
```

## Documentation Template
```markdown
# iOS App Structure Analysis

## Application Details
- Bundle ID:
- Version:
- Deployment Target:

## Structure Analysis
### Bundle Contents
- [ ] Binary executable
- [ ] Resources
- [ ] Frameworks
- [ ] Configuration files

### Security Configuration
- [ ] Data protection
- [ ] URL schemes
- [ ] Network security
- [ ] Privacy permissions

## Recommendations
1. Structure:
   - Current:
   - Suggested:
   - Priority:

2. Security:
   - Issues:
   - Solutions:
   - Timeline:
```

## Best Practices

### 1. File Organization
- Use proper app directories
- Implement data protection
- Secure sensitive files
- Clean up temporary files
- Validate file access

### 2. Security Implementation
- Enable code signing
- Configure entitlements
- Implement SSL pinning
- Use secure coding practices
- Protect sensitive data

## Troubleshooting Guide

### Common Issues
1. File Access
   - Permission errors
   - Protection failures
   - Directory structure

2. Security Violations
   - Code signing
   - Entitlements
   - Data protection

## Resources
1. Apple Documentation
2. Security Guidelines
3. Sample Code
4. Developer Forums
