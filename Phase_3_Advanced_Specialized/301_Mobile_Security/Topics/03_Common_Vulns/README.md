# Common Mobile Vulnerabilities

## Introduction
This guide covers common vulnerabilities found in mobile applications, including both Android and iOS platforms. The content progresses from basic security issues to advanced exploitation techniques.

## Key Terminology

### Basic Concepts

#### Mobile Vulnerabilities
- **Definition**: Security weaknesses in mobile apps
- **Impact**:
  - Data exposure
  - System compromise
  - Privacy violation
  - Financial loss
- **Scope**: Both Android and iOS platforms

#### Attack Surface
- **Definition**: Points of potential exploitation
- **Areas**:
  - Network communication
  - Data storage
  - Input handling
  - Authentication
  - Authorization

### Common Vulnerabilities

#### 1. Insecure Data Storage
- **Definition**: Improper data protection
- **Examples**:
```java
// Android example - Insecure storage
SharedPreferences prefs = getSharedPreferences("app_prefs", MODE_PRIVATE);
prefs.edit().putString("password", "secret123").apply();

// iOS example - Insecure storage
UserDefaults.standard.set("secret123", forKey: "password")
```

#### 2. Weak Network Security
- **Definition**: Inadequate communication protection
- **Issues**:
```swift
// iOS example - Disabled ATS
<key>NSAppTransportSecurity</key>
<dict>
    <key>NSAllowsArbitraryLoads</key>
    <true/>
</dict>

// Android example - Clear text traffic
android:usesCleartextTraffic="true"
```

## Advanced Vulnerabilities

### 1. Code Injection
#### SQL Injection
- **Definition**: Database query manipulation
- **Example**:
```java
// Vulnerable query
String query = "SELECT * FROM users WHERE username = '" + userInput + "'";

// Secure query
String query = "SELECT * FROM users WHERE username = ?";
PreparedStatement stmt = conn.prepareStatement(query);
stmt.setString(1, userInput);
```

#### JavaScript Injection
- **Definition**: Malicious JS execution
- **Prevention**:
```java
// Android WebView protection
webView.setWebViewClient(new WebViewClient() {
    @Override
    public boolean shouldOverrideUrlLoading(WebView view, String url) {
        if (url.startsWith("javascript:")) {
            return true; // Block JavaScript URLs
        }
        return false;
    }
});
```

### 2. Authentication Bypass
#### Token Manipulation
- **Definition**: Tampering with auth tokens
- **Example**:
```java
// Vulnerable token handling
String token = getStoredToken();
if (token != null) {
    makeAuthenticatedRequest(token);
}

// Secure token handling
String token = getStoredToken();
if (validateToken(token)) {
    makeAuthenticatedRequest(token);
}
```

#### Session Management
- **Definition**: Session handling issues
- **Implementation**:
```swift
// iOS secure session handling
class SessionManager {
    static func validateSession() -> Bool {
        guard let token = KeychainWrapper.standard.string(forKey: "sessionToken"),
              let expiry = KeychainWrapper.standard.date(forKey: "tokenExpiry")
        else {
            return false
        }
        return Date() < expiry
    }
}
```

## Security Testing

### 1. Vulnerability Scanning
#### Static Analysis
- **Definition**: Code-level vulnerability detection
- **Tools**:
  - MobSF
  - QARK
  - SonarQube
- **Process**:
```bash
# MobSF scan
mobsf --static app.apk

# QARK scan
qark --apk app.apk --report-type json
```

#### Dynamic Analysis
- **Definition**: Runtime vulnerability detection
- **Tools**:
  - Frida
  - Burp Suite
  - OWASP ZAP
- **Example**:
```javascript
// Frida vulnerability detection
Interceptor.attach(ptr(funcAddr), {
    onEnter: function(args) {
        console.log('Potential vulnerability in:', this.context.pc);
    }
});
```

## Lab Exercises

### Exercise 1: Basic Vulnerabilities
1. **Data Storage Analysis**
   - Definition: Finding storage vulnerabilities
   - Steps:
     - File system analysis
     - Database inspection
     - Preference examination

2. **Network Security**
   - Definition: Testing communication security
   - Process:
     - Traffic inspection
     - Certificate validation
     - Protocol analysis

### Exercise 2: Advanced Exploitation
1. **Injection Testing**
   - Definition: Testing input handling
   - Implementation:
     - Input identification
     - Payload creation
     - Exploitation attempt

2. **Authentication Testing**
   - Definition: Testing auth mechanisms
   - Methods:
     - Token analysis
     - Session testing
     - Bypass attempts

## Documentation Template
```markdown
# Vulnerability Assessment Report

## Application Details
- Name:
- Platform:
- Version:

## Vulnerabilities
### High Risk
1. Issue:
   - Description:
   - Impact:
   - Mitigation:

### Medium Risk
1. Issue:
   - Description:
   - Impact:
   - Mitigation:

## Testing Details
### Methodology
1. Approach:
   - Tools:
   - Process:
   - Results:
```

## Best Practices

### 1. Prevention
#### Secure Development
- **Definition**: Security-first coding
- **Guidelines**:
  - Input validation
  - Output encoding
  - Secure storage
  - Proper authentication

#### Security Controls
- **Definition**: Protective measures
- **Implementation**:
  - Access control
  - Encryption
  - Secure communication
  - Logging

### 2. Mitigation
#### Vulnerability Response
- **Definition**: Handling security issues
- **Process**:
  - Issue identification
  - Risk assessment
  - Patch development
  - Deployment

#### Security Updates
- **Definition**: Maintaining security
- **Requirements**:
  - Regular updates
  - Security patches
  - User notification

## Troubleshooting

### Common Issues
1. **False Positives**
   - Definition: Incorrect vulnerability reports
   - Solutions:
     - Manual verification
     - Context analysis
     - Tool calibration

2. **Exploitation Failures**
   - Definition: Failed security tests
   - Solutions:
     - Method review
     - Tool updates
     - Approach modification

## Resources
1. OWASP Mobile Top 10
2. CWE Database
3. Testing Tools
4. Security Communities

## Next Steps
1. Study vulnerabilities
2. Practice exploitation
3. Learn mitigation
4. Join security groups
