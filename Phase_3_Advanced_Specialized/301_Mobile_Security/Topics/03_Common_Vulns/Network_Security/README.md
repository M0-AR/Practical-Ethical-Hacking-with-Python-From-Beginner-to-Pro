# Mobile Network Security

## Introduction
Network security is crucial for mobile applications to protect data in transit. This guide covers common network vulnerabilities and their mitigations for both Android and iOS platforms.

## Basic Concepts

### 1. SSL/TLS Implementation

#### Certificate Validation
```java
// Android Implementation
public class SSLPinningManager {
    private final String[] validPins = {
        "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        "sha256/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
    };
    
    private OkHttpClient createPinnedClient() {
        CertificatePinner pinner = new CertificatePinner.Builder()
            .add("api.example.com", validPins)
            .build();
            
        return new OkHttpClient.Builder()
            .certificatePinner(pinner)
            .build();
    }
}
```

```swift
// iOS Implementation
class SSLPinningManager: NSObject, URLSessionDelegate {
    private let pinnedCertificates: [Data]
    
    override init() {
        let certificates = [
            "cert1", "cert2"  // Certificate names
        ]
        
        pinnedCertificates = certificates.compactMap { name in
            guard let path = Bundle.main.path(forResource: name, ofType: "cer"),
                  let data = try? Data(contentsOf: URL(fileURLWithPath: path)) else {
                return nil
            }
            return data
        }
        
        super.init()
    }
    
    func urlSession(_ session: URLSession,
                   didReceive challenge: URLAuthenticationChallenge,
                   completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        
        guard let serverTrust = challenge.protectionSpace.serverTrust,
              let certificate = SecTrustGetCertificateAtIndex(serverTrust, 0) else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        
        let serverCertificateData = SecCertificateCopyData(certificate) as Data
        
        if pinnedCertificates.contains(serverCertificateData) {
            completionHandler(.useCredential, URLCredential(trust: serverTrust))
        } else {
            completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }
}
```

### 2. Network Request Security

#### Secure HTTP Client
```java
// Android secure HTTP client
public class SecureNetworkClient {
    private static final int TIMEOUT = 30_000;
    private final OkHttpClient client;
    
    public SecureNetworkClient() {
        client = new OkHttpClient.Builder()
            .connectTimeout(TIMEOUT, TimeUnit.MILLISECONDS)
            .readTimeout(TIMEOUT, TimeUnit.MILLISECONDS)
            .writeTimeout(TIMEOUT, TimeUnit.MILLISECONDS)
            .followRedirects(false)  // Prevent redirect attacks
            .followSslRedirects(false)
            .certificatePinner(createCertificatePinner())
            .build();
    }
    
    public Response makeRequest(String url, String method, Map<String, String> headers,
                              RequestBody body) throws IOException {
        Request.Builder requestBuilder = new Request.Builder()
            .url(url)
            .method(method, body);
            
        // Add security headers
        headers.put("X-Content-Type-Options", "nosniff");
        headers.put("X-Frame-Options", "DENY");
        headers.put("X-XSS-Protection", "1; mode=block");
        
        for (Map.Entry<String, String> header : headers.entrySet()) {
            requestBuilder.addHeader(header.getKey(), header.getValue());
        }
        
        return client.newCall(requestBuilder.build()).execute();
    }
}
```

```swift
// iOS secure HTTP client
class SecureNetworkClient {
    private let session: URLSession
    
    init() {
        let config = URLSessionConfiguration.default
        config.timeoutIntervalForRequest = 30
        config.timeoutIntervalForResource = 300
        
        // Security configuration
        config.tlsMinimumSupportedProtocol = .tlsProtocol12
        config.httpAdditionalHeaders = [
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1; mode=block"
        ]
        
        session = URLSession(configuration: config,
                           delegate: SSLPinningManager(),
                           delegateQueue: nil)
    }
    
    func makeRequest(url: URL,
                    method: String,
                    headers: [String: String],
                    body: Data?) async throws -> (Data, URLResponse) {
        var request = URLRequest(url: url)
        request.httpMethod = method
        request.httpBody = body
        
        // Add headers
        headers.forEach { request.addValue($1, forHTTPHeaderField: $0) }
        
        return try await session.data(for: request)
    }
}
```

### 3. Common Vulnerabilities

#### Man-in-the-Middle Protection
```java
// Android MITM protection
public class MITMProtection {
    private static final Set<String> PINNED_DOMAINS = new HashSet<>(Arrays.asList(
        "api.example.com",
        "auth.example.com"
    ));
    
    public static OkHttpClient createSecureClient() {
        return new OkHttpClient.Builder()
            .certificatePinner(createCertificatePinner())
            .addInterceptor(new SecurityInterceptor())
            .build();
    }
    
    private static class SecurityInterceptor implements Interceptor {
        @Override
        public Response intercept(Chain chain) throws IOException {
            Request request = chain.request();
            
            // Verify domain
            String host = request.url().host();
            if (!PINNED_DOMAINS.contains(host)) {
                throw new SecurityException("Unauthorized domain: " + host);
            }
            
            // Check for proxy
            if (isProxyDetected()) {
                throw new SecurityException("Proxy detected");
            }
            
            return chain.proceed(request);
        }
        
        private boolean isProxyDetected() {
            String proxyHost = System.getProperty("http.proxyHost");
            String proxyPort = System.getProperty("http.proxyPort");
            return proxyHost != null && proxyPort != null;
        }
    }
}
```

#### Traffic Analysis Protection
```java
// Network traffic protection
public class TrafficProtection {
    private static final String ENCRYPTION_ALGORITHM = "AES/GCM/NoPadding";
    private final SecretKey encryptionKey;
    
    public byte[] securePayload(byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, encryptionKey);
        
        byte[] iv = cipher.getIV();
        byte[] encrypted = cipher.doFinal(data);
        
        // Combine IV and encrypted data
        ByteBuffer buffer = ByteBuffer.allocate(iv.length + encrypted.length);
        buffer.put(iv);
        buffer.put(encrypted);
        return buffer.array();
    }
    
    public byte[] processResponse(byte[] encryptedData) throws Exception {
        ByteBuffer buffer = ByteBuffer.wrap(encryptedData);
        
        byte[] iv = new byte[12];  // GCM IV size
        buffer.get(iv);
        
        byte[] encrypted = new byte[buffer.remaining()];
        buffer.get(encrypted);
        
        Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.DECRYPT_MODE, encryptionKey, spec);
        
        return cipher.doFinal(encrypted);
    }
}
```

### 4. Advanced Security Measures

#### Network Security Configuration
```xml
<!-- Android network security config -->
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <domain-config cleartextTrafficPermitted="false">
        <domain includeSubdomains="true">example.com</domain>
        <pin-set expiration="2024-01-01">
            <pin digest="SHA-256">k3XnEYQCK79AtL9GYnT/nxOWPAzNqM8rB/GYKNK4+3c=</pin>
            <pin digest="SHA-256">YZPgTZ+woNCCCIW3LH2CxQeLzB/1m42QcCTBSdgayjs=</pin>
        </pin-set>
        <trust-anchors>
            <certificates src="system"/>
            <certificates src="user"/>
        </trust-anchors>
    </domain-config>
</network-security-config>
```

```swift
// iOS ATS configuration
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
            <key>NSIncludesSubdomains</key>
            <true/>
        </dict>
    </dict>
</dict>
```

## Testing Methodologies

### 1. Network Analysis
```python
# Network analysis script
def analyze_network_security():
    # Test cases
    test_cases = [
        check_ssl_pinning,
        check_certificate_validation,
        check_mitm_protection,
        check_traffic_encryption
    ]
    
    for test in test_cases:
        try:
            test()
        except Exception as e:
            print(f"Test failed: {test.__name__}")
            print(f"Error: {e}")

def check_ssl_pinning():
    # Setup proxy
    proxy = mitmproxy.start()
    
    try:
        # Make request
        response = requests.get("https://api.example.com",
                              proxies={"https": "http://localhost:8080"})
        
        # If request succeeds with proxy, pinning might be broken
        print("WARNING: SSL pinning might be bypassed")
    except requests.exceptions.SSLError:
        print("SSL pinning working as expected")
    finally:
        proxy.stop()

def check_certificate_validation():
    # Test with invalid certificate
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    
    try:
        response = requests.get("https://api.example.com",
                              verify=False)
        print("WARNING: Certificate validation might be disabled")
    except requests.exceptions.SSLError:
        print("Certificate validation working as expected")
```

### 2. Traffic Analysis
```python
# Traffic analysis script
def analyze_traffic():
    # Start packet capture
    capture = pyshark.LiveCapture(interface='eth0')
    
    try:
        for packet in capture.sniff_continuously(packet_count=100):
            analyze_packet(packet)
    finally:
        capture.close()

def analyze_packet(packet):
    # Check for sensitive data
    patterns = [
        r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',  # Email
        r'\b\d{16}\b',  # Credit card
        r'\b[A-Za-z0-9]{32}\b',  # MD5 hash
        r'\b[A-Za-z0-9+/]{64}\b'  # Base64
    ]
    
    for pattern in patterns:
        if re.search(pattern, str(packet)):
            print(f"Found potential sensitive data in packet: {packet}")
```

## Documentation Template
```markdown
# Network Security Analysis

## Implementation Review
### SSL/TLS
- Version:
- Configuration:
- Pinning:

### Request Security
- Headers:
- Encryption:
- Authentication:

## Vulnerability Assessment
### MITM Protection
1. Certificate Pinning:
   - Implementation:
   - Effectiveness:
   - Bypass Attempts:

2. Traffic Protection:
   - Encryption:
   - Headers:
   - Protocols:

## Testing Results
### Security Tests
1. Test Case:
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
- Use SSL/TLS pinning
- Implement HTTPS only
- Add security headers
- Monitor network traffic
- Regular security updates

### 2. Security Measures
- Encrypt all traffic
- Validate certificates
- Implement pinning
- Use secure protocols
- Monitor for attacks

## Troubleshooting Guide

### Common Issues
1. Connection Failures
   - Certificate issues
   - Pinning failures
   - Protocol errors

2. Security Violations
   - MITM attacks
   - Certificate issues
   - Protocol downgrades

## Resources
1. OWASP Mobile Security Guide
2. Network Security Tools
3. SSL/TLS Documentation
4. Developer Forums
