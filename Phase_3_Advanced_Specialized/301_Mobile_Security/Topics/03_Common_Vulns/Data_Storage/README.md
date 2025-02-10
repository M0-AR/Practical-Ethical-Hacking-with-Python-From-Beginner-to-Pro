# Mobile Data Storage Security

## Introduction
Secure data storage is crucial for mobile applications. This guide covers common vulnerabilities in data storage and their mitigations for both Android and iOS platforms.

## Basic Concepts

### 1. Data Storage Types

#### Internal Storage
```java
// Android Implementation
public class InternalStorageManager {
    private Context context;
    
    public void saveData(String filename, String data) {
        // Vulnerable: Plain text storage
        try (FileOutputStream fos = context.openFileOutput(filename, Context.MODE_PRIVATE)) {
            fos.write(data.getBytes());
        }
        
        // Secure: Encrypted storage
        try {
            byte[] encryptedData = encrypt(data.getBytes());
            try (FileOutputStream fos = context.openFileOutput(filename, Context.MODE_PRIVATE)) {
                fos.write(encryptedData);
            }
        } catch (Exception e) {
            throw new SecurityException("Encryption failed", e);
        }
    }
    
    private byte[] encrypt(byte[] data) throws Exception {
        SecretKey key = getEncryptionKey();
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        
        byte[] iv = cipher.getIV();
        byte[] encrypted = cipher.doFinal(data);
        
        // Combine IV and encrypted data
        ByteBuffer buffer = ByteBuffer.allocate(iv.length + encrypted.length);
        buffer.put(iv);
        buffer.put(encrypted);
        return buffer.array();
    }
}
```

```swift
// iOS Implementation
class InternalStorageManager {
    func saveData(_ data: Data, filename: String) throws {
        // Get documents directory
        guard let documentsPath = FileManager.default.urls(for: .documentDirectory,
                                                         in: .userDomainMask).first else {
            throw StorageError.pathNotFound
        }
        
        let fileURL = documentsPath.appendingPathComponent(filename)
        
        // Encrypt data
        let encryptedData = try encryptData(data)
        
        // Save with data protection
        try encryptedData.write(to: fileURL, options: .completeFileProtection)
    }
    
    private func encryptData(_ data: Data) throws -> Data {
        let key = try getEncryptionKey()
        
        guard let encrypted = try? ChaChaPoly.seal(data, using: key).combined else {
            throw StorageError.encryptionFailed
        }
        
        return encrypted
    }
}
```

#### Shared Preferences / UserDefaults
```java
// Android SharedPreferences
public class SecurePreferences {
    private SharedPreferences preferences;
    private Cipher cipher;
    private SecretKey key;
    
    public void saveSecure(String key, String value) {
        try {
            String encryptedValue = encrypt(value);
            preferences.edit().putString(key, encryptedValue).apply();
        } catch (Exception e) {
            throw new SecurityException("Failed to save secure preference", e);
        }
    }
    
    public String getSecure(String key) {
        try {
            String encryptedValue = preferences.getString(key, null);
            if (encryptedValue == null) return null;
            return decrypt(encryptedValue);
        } catch (Exception e) {
            throw new SecurityException("Failed to retrieve secure preference", e);
        }
    }
}
```

```swift
// iOS UserDefaults
class SecureDefaults {
    private let defaults = UserDefaults.standard
    private let keychain = KeychainWrapper.standard
    
    func saveSecure(_ value: String, forKey key: String) {
        // Generate random key for value encryption
        let valueKey = UUID().uuidString
        
        // Encrypt value
        guard let encryptedValue = encrypt(value, withKey: valueKey) else {
            return
        }
        
        // Store encrypted value in UserDefaults
        defaults.set(encryptedValue, forKey: key)
        
        // Store encryption key in Keychain
        keychain.set(valueKey, forKey: key)
    }
    
    func getSecure(forKey key: String) -> String? {
        guard let encryptedValue = defaults.string(forKey: key),
              let valueKey = keychain.string(forKey: key) else {
            return nil
        }
        
        return decrypt(encryptedValue, withKey: valueKey)
    }
}
```

### 2. Common Vulnerabilities

#### Insecure File Storage
```java
// Vulnerable file storage
public class VulnerableStorage {
    public void saveCredentials(String username, String password) {
        // Vulnerable: Plain text storage
        try (FileWriter writer = new FileWriter("credentials.txt")) {
            writer.write(username + ":" + password);
        }
    }
}

// Secure file storage
public class SecureStorage {
    public void saveCredentials(String username, String password) {
        // Hash password
        String hashedPassword = hashPassword(password);
        
        // Encrypt credentials
        byte[] encryptedData = encryptCredentials(username, hashedPassword);
        
        // Save with proper permissions
        try (FileOutputStream fos = context.openFileOutput(
                "credentials.enc", Context.MODE_PRIVATE)) {
            fos.write(encryptedData);
        }
    }
    
    private String hashPassword(String password) {
        // Implement secure password hashing
        return BCrypt.hashpw(password, BCrypt.gensalt(12));
    }
}
```

#### Database Security
```java
// Vulnerable SQLite usage
public class VulnerableDatabase {
    public void saveUser(String username, String password) {
        // Vulnerable: Plain text storage and SQL injection
        String sql = "INSERT INTO users (username, password) VALUES ('" +
                    username + "', '" + password + "')";
        db.execSQL(sql);
    }
}

// Secure SQLite usage
public class SecureDatabase {
    public void saveUser(String username, String password) {
        // Use parameterized query
        SQLiteDatabase db = getWritableDatabase();
        ContentValues values = new ContentValues();
        values.put("username", username);
        values.put("password", hashPassword(password));
        
        // Encrypt database
        db.insert("users", null, values);
    }
    
    private SQLiteDatabase getWritableDatabase() {
        // Configure database encryption
        SQLiteDatabaseHook hook = new SQLiteDatabaseHook() {
            public void preKey(SQLiteDatabase database) {}
            public void postKey(SQLiteDatabase database) {
                database.rawExecSQL("PRAGMA cipher_compatibility = 4");
                database.rawExecSQL("PRAGMA kdf_iter = 64000");
                database.rawExecSQL("PRAGMA cipher_page_size = 4096");
            }
        };
        
        return SQLiteDatabase.openOrCreateDatabase(dbFile, dbKey, null, hook);
    }
}
```

### 3. Encryption Implementation

#### Key Management
```java
// Android key management
public class KeyManager {
    private static final String MASTER_KEY_ALIAS = "master_key";
    
    public SecretKey getMasterKey() throws Exception {
        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);
        
        if (!keyStore.containsAlias(MASTER_KEY_ALIAS)) {
            generateMasterKey();
        }
        
        KeyStore.SecretKeyEntry entry = (KeyStore.SecretKeyEntry)
            keyStore.getEntry(MASTER_KEY_ALIAS, null);
        return entry.getSecretKey();
    }
    
    private void generateMasterKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
            
        KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(
            MASTER_KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .build();
            
        keyGen.init(spec);
        keyGen.generateKey();
    }
}
```

```swift
// iOS key management
class KeyManager {
    private let tag = "com.example.masterkey".data(using: .utf8)!
    
    func getMasterKey() throws -> SecKey {
        // Check for existing key
        var query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecReturnRef as String: true
        ]
        
        var key: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &key)
        
        if status == errSecSuccess {
            return key as! SecKey
        }
        
        // Generate new key
        return try generateMasterKey()
    }
    
    private func generateMasterKey() throws -> SecKey {
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits as String: 2048,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: tag
            ]
        ]
        
        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            throw error!.takeRetainedValue() as Error
        }
        
        return key
    }
}
```

### 4. Secure Data Types

#### Sensitive Data Handling
```java
// Android secure string
public class SecureString {
    private char[] value;
    
    public SecureString(String input) {
        this.value = input.toCharArray();
    }
    
    public void clear() {
        if (value != null) {
            for (int i = 0; i < value.length; i++) {
                value[i] = '\0';
            }
            value = null;
        }
    }
    
    @Override
    protected void finalize() throws Throwable {
        clear();
        super.finalize();
    }
}
```

```swift
// iOS secure data
class SecureData {
    private var data: Data
    
    init(data: Data) {
        self.data = data
        // Mark memory as sensitive
        self.data.withUnsafeMutableBytes { ptr in
            mlock(ptr.baseAddress, ptr.count)
        }
    }
    
    deinit {
        // Clear and unlock memory
        data.withUnsafeMutableBytes { ptr in
            memset(ptr.baseAddress, 0, ptr.count)
            munlock(ptr.baseAddress, ptr.count)
        }
    }
}
```

## Testing Methodologies

### 1. Storage Analysis
```python
# Storage analysis script
def analyze_storage():
    # Test cases
    storage_locations = [
        "/data/data/com.example.app/shared_prefs/",
        "/data/data/com.example.app/databases/",
        "/data/data/com.example.app/files/"
    ]
    
    for location in storage_locations:
        analyze_files(location)
        check_permissions(location)
        scan_for_sensitive_data(location)

def scan_for_sensitive_data(path):
    patterns = [
        r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',  # Email
        r'\b\d{16}\b',  # Credit card
        r'\b[A-Za-z0-9]{32}\b',  # MD5 hash
        r'\b[A-Za-z0-9+/]{64}\b'  # Base64
    ]
    
    for pattern in patterns:
        matches = find_pattern_in_files(path, pattern)
        if matches:
            print(f"Found potential sensitive data: {matches}")
```

### 2. Encryption Analysis
```python
# Encryption analysis script
def analyze_encryption():
    # Check for weak encryption
    check_encryption_algorithms()
    check_key_storage()
    check_initialization_vectors()

def check_encryption_algorithms():
    weak_algorithms = [
        'DES',
        'RC4',
        'MD5',
        'SHA1'
    ]
    
    # Search for weak algorithm usage
    for algo in weak_algorithms:
        occurrences = search_codebase(algo)
        if occurrences:
            print(f"Found weak algorithm {algo} in: {occurrences}")

def check_key_storage():
    # Check for hardcoded keys
    key_patterns = [
        r'private.*key.*=.*"[A-Za-z0-9+/=]+"',
        r'secret.*=.*"[A-Za-z0-9+/=]+"'
    ]
    
    for pattern in key_patterns:
        matches = search_codebase(pattern)
        if matches:
            print(f"Found potential hardcoded keys: {matches}")
```

## Documentation Template
```markdown
# Data Storage Security Analysis

## Storage Implementation
### Internal Storage
- Type:
- Security:
- Encryption:

### External Storage
- Usage:
- Protection:
- Risks:

### Database
- Type:
- Encryption:
- Access Control:

## Security Assessment
### Encryption
1. Algorithm:
   - Type:
   - Strength:
   - Implementation:

2. Key Management:
   - Storage:
   - Protection:
   - Rotation:

### Vulnerabilities
1. Finding:
   - Description:
   - Risk Level:
   - Mitigation:

## Recommendations
1. Implementation:
   - Current:
   - Suggested:
   - Priority:
```

## Best Practices

### 1. Implementation Guidelines
- Use encryption for sensitive data
- Implement secure key storage
- Use proper file permissions
- Implement data sanitization
- Regular security audits

### 2. Security Measures
- Encrypt all sensitive data
- Use secure storage locations
- Implement access controls
- Regular data cleanup
- Monitor storage usage

## Troubleshooting Guide

### Common Issues
1. Storage Failures
   - Permission errors
   - Encryption issues
   - Space constraints

2. Security Violations
   - Data leaks
   - Encryption failures
   - Permission bypass

## Resources
1. OWASP Mobile Security Guide
2. Encryption Libraries
3. Security Tools
4. Developer Forums
