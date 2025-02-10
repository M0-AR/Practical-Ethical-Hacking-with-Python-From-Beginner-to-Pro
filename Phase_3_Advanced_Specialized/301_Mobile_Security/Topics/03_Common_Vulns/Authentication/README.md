# Mobile Authentication Vulnerabilities

## Introduction
Authentication vulnerabilities in mobile applications can lead to unauthorized access and data breaches. This guide covers common authentication vulnerabilities and their mitigations.

## Basic Concepts

### 1. Authentication Types

#### Token-Based Authentication
```java
// Android Implementation
public class TokenAuthenticator {
    private static final String TOKEN_PREF = "auth_token";
    private SharedPreferences prefs;
    
    public void storeToken(String token) {
        // Vulnerable: Storing token in plain text
        prefs.edit().putString(TOKEN_PREF, token).apply();
        
        // Secure: Encrypt token before storage
        String encryptedToken = encryptToken(token);
        prefs.edit().putString(TOKEN_PREF, encryptedToken).apply();
    }
    
    private String encryptToken(String token) {
        // Implement encryption
        return EncryptionUtil.encrypt(token);
    }
}
```

```swift
// iOS Implementation
class TokenAuthenticator {
    private let keychain = KeychainWrapper.standard
    
    func storeToken(_ token: String) {
        // Vulnerable: NSUserDefaults storage
        UserDefaults.standard.set(token, forKey: "auth_token")
        
        // Secure: Keychain storage
        keychain.set(token, forKey: "auth_token",
                    withAccessibility: .whenUnlockedThisDeviceOnly)
    }
}
```

#### Biometric Authentication
```java
// Android Biometric
public class BiometricAuth {
    private BiometricPrompt biometricPrompt;
    
    public void authenticate() {
        BiometricPrompt.PromptInfo promptInfo = new BiometricPrompt.PromptInfo.Builder()
            .setTitle("Biometric Authentication")
            .setSubtitle("Log in using your biometric credential")
            .setNegativeButtonText("Cancel")
            .build();
            
        biometricPrompt.authenticate(promptInfo);
    }
    
    private BiometricPrompt.AuthenticationCallback getCallback() {
        return new BiometricPrompt.AuthenticationCallback() {
            @Override
            public void onAuthenticationSucceeded(BiometricPrompt.AuthenticationResult result) {
                // Implement post-authentication logic
            }
            
            @Override
            public void onAuthenticationFailed() {
                // Handle failure
            }
        };
    }
}
```

```swift
// iOS Biometric
class BiometricAuth {
    let context = LAContext()
    
    func authenticate() {
        var error: NSError?
        
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics,
                                      error: &error) else {
            // Handle not available
            return
        }
        
        context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics,
                             localizedReason: "Log in with biometric") { success, error in
            if success {
                // Handle success
            } else {
                // Handle error
            }
        }
    }
}
```

### 2. Common Vulnerabilities

#### Weak Password Policies
```java
// Vulnerable password validation
public boolean isPasswordValid(String password) {
    return password.length() >= 6;
}

// Secure password validation
public boolean isPasswordSecure(String password) {
    // Length check
    if (password.length() < 12) return false;
    
    // Complexity checks
    boolean hasUpper = false;
    boolean hasLower = false;
    boolean hasDigit = false;
    boolean hasSpecial = false;
    
    for (char c : password.toCharArray()) {
        if (Character.isUpperCase(c)) hasUpper = true;
        if (Character.isLowerCase(c)) hasLower = true;
        if (Character.isDigit(c)) hasDigit = true;
        if ("!@#$%^&*()_+-=[]{}|;:,.<>?".indexOf(c) >= 0) hasSpecial = true;
    }
    
    return hasUpper && hasLower && hasDigit && hasSpecial;
}
```

#### Token Exposure
```java
// Vulnerable token handling
public class VulnerableTokenManager {
    public void sendRequest(String url) {
        // Token in URL (Vulnerable)
        String requestUrl = url + "?token=" + getAuthToken();
        
        // Log token (Vulnerable)
        Log.d("Auth", "Using token: " + getAuthToken());
    }
}

// Secure token handling
public class SecureTokenManager {
    public void sendRequest(String url) {
        HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
        // Token in header
        conn.setRequestProperty("Authorization", "Bearer " + getAuthToken());
        
        // No logging of sensitive data
        Log.d("Auth", "Sending authenticated request");
    }
}
```

#### Session Management
```java
// Vulnerable session handling
public class VulnerableSessionManager {
    private String sessionId;
    
    public void createSession() {
        // Predictable session ID
        sessionId = String.valueOf(System.currentTimeMillis());
    }
}

// Secure session handling
public class SecureSessionManager {
    private String sessionId;
    
    public void createSession() {
        // Secure random session ID
        byte[] bytes = new byte[32];
        SecureRandom random = new SecureRandom();
        random.nextBytes(bytes);
        sessionId = Base64.encodeToString(bytes, Base64.NO_WRAP);
    }
    
    public void invalidateSession() {
        sessionId = null;
        clearSessionData();
    }
}
```

### 3. Authentication Bypass Techniques

#### Client-Side Validation Bypass
```javascript
// Frida script to bypass authentication
Java.perform(function() {
    var LoginManager = Java.use("com.example.app.LoginManager");
    
    LoginManager.isAuthenticated.implementation = function() {
        console.log("Bypassing authentication check");
        return true;
    };
});
```

#### Token Manipulation
```python
# Token manipulation script
import jwt

# Read token
token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."

# Decode without verification
decoded = jwt.decode(token, verify=False)

# Modify claims
decoded['role'] = 'admin'

# Create new token
new_token = jwt.encode(decoded, 'guess_the_key')
```

## Security Implementation

### 1. Secure Authentication Flow
```java
public class SecureAuthenticationManager {
    private static final int MAX_ATTEMPTS = 3;
    private int failedAttempts = 0;
    private long lockoutTime = 0;
    
    public boolean authenticate(String username, String password) {
        // Check lockout
        if (isLockedOut()) {
            throw new SecurityException("Account is locked");
        }
        
        try {
            // Verify credentials
            if (verifyCredentials(username, password)) {
                resetFailedAttempts();
                return true;
            } else {
                handleFailedAttempt();
                return false;
            }
        } catch (Exception e) {
            handleFailedAttempt();
            throw new SecurityException("Authentication failed");
        }
    }
    
    private boolean isLockedOut() {
        if (lockoutTime == 0) return false;
        
        long currentTime = System.currentTimeMillis();
        if (currentTime < lockoutTime) {
            return true;
        }
        
        // Reset if lockout expired
        lockoutTime = 0;
        failedAttempts = 0;
        return false;
    }
    
    private void handleFailedAttempt() {
        failedAttempts++;
        if (failedAttempts >= MAX_ATTEMPTS) {
            // Lock for 30 minutes
            lockoutTime = System.currentTimeMillis() + (30 * 60 * 1000);
        }
    }
}
```

### 2. Multi-Factor Authentication
```swift
class MFAManager {
    enum MFAMethod {
        case sms
        case email
        case authenticator
    }
    
    func initiateMFA(method: MFAMethod, completion: @escaping (Bool) -> Void) {
        switch method {
        case .sms:
            sendSMSCode { success in
                completion(success)
            }
        case .email:
            sendEmailCode { success in
                completion(success)
            }
        case .authenticator:
            verifyAuthenticatorCode { success in
                completion(success)
            }
        }
    }
    
    private func generateTOTP() -> String {
        // Generate time-based one-time password
        let period: TimeInterval = 30
        let time = Date().timeIntervalSince1970
        let counter = UInt64(time / period)
        
        return generateHOTP(counter: counter)
    }
    
    private func generateHOTP(counter: UInt64) -> String {
        // Implement HOTP generation
        return "000000" // Placeholder
    }
}
```

## Testing Methodologies

### 1. Authentication Testing
```python
# Authentication test script
def test_authentication():
    # Test cases
    test_cases = [
        {"username": "admin", "password": ""},  # Empty password
        {"username": "admin", "password": "admin"},  # Default credentials
        {"username": "' OR '1'='1", "password": ""},  # SQL injection
        {"username": "<script>alert(1)</script>", "password": "test"},  # XSS
        {"username": "admin", "password": "a" * 1000}  # Buffer overflow
    ]
    
    for test in test_cases:
        response = send_auth_request(test["username"], test["password"])
        analyze_response(response)

def analyze_response(response):
    # Check for security headers
    security_headers = [
        "X-Frame-Options",
        "X-XSS-Protection",
        "X-Content-Type-Options",
        "Strict-Transport-Security"
    ]
    
    for header in security_headers:
        if header not in response.headers:
            print(f"Missing security header: {header}")
    
    # Check for sensitive data exposure
    if "token" in response.text or "key" in response.text:
        print("Possible sensitive data exposure in response")
```

### 2. Token Analysis
```python
# Token analysis script
import jwt
from cryptography.hazmat.primitives import hashes

def analyze_token(token):
    # Decode without verification
    try:
        header = jwt.get_unverified_header(token)
        payload = jwt.decode(token, verify=False)
        
        # Check algorithm
        if header["alg"] == "none":
            print("WARNING: Token uses 'none' algorithm")
        
        if header["alg"] == "HS256":
            test_weak_secrets(token)
        
        # Check claims
        check_claims(payload)
        
    except Exception as e:
        print(f"Token analysis failed: {e}")

def test_weak_secrets(token):
    common_secrets = [
        "secret",
        "key",
        "password",
        "1234567890",
        ""
    ]
    
    for secret in common_secrets:
        try:
            jwt.decode(token, secret)
            print(f"WARNING: Token verified with weak secret: {secret}")
            break
        except:
            continue

def check_claims(payload):
    # Check expiration
    if "exp" not in payload:
        print("WARNING: Token has no expiration claim")
    
    # Check issuer
    if "iss" not in payload:
        print("WARNING: Token has no issuer claim")
    
    # Check audience
    if "aud" not in payload:
        print("WARNING: Token has no audience claim")
```

## Documentation Template
```markdown
# Authentication Security Analysis

## Implementation Review
### Authentication Method
- Type:
- Implementation:
- Security Level:

### Vulnerability Assessment
1. Password Policy:
   - Minimum Length:
   - Complexity Rules:
   - Implementation:

2. Token Security:
   - Type:
   - Storage:
   - Transmission:

3. Session Management:
   - Creation:
   - Expiration:
   - Invalidation:

## Testing Results
### Authentication Tests
1. Test Case:
   - Input:
   - Expected:
   - Result:

### Security Tests
1. Test:
   - Method:
   - Finding:
   - Risk Level:

## Recommendations
1. Implementation:
   - Current:
   - Suggested:
   - Priority:
```

## Best Practices

### 1. Implementation Guidelines
- Use secure password storage
- Implement MFA
- Use secure session management
- Implement rate limiting
- Monitor authentication attempts

### 2. Security Measures
- Encrypt sensitive data
- Use secure protocols
- Implement logging
- Regular security updates
- User activity monitoring

## Troubleshooting Guide

### Common Issues
1. Authentication Failures
   - Check credentials
   - Verify token validity
   - Check session state

2. Security Violations
   - Monitor attempts
   - Check for attacks
   - Review logs

## Resources
1. OWASP Mobile Security Guide
2. Authentication Libraries
3. Security Tools
4. Developer Forums
