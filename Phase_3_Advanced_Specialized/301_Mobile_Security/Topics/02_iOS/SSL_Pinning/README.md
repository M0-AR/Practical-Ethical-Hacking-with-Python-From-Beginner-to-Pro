# SSL Pinning in iOS

## Introduction to SSL Pinning

SSL Pinning is a security technique that helps prevent man-in-the-middle (MITM) attacks by validating the server's certificate against a known good certificate or public key.

## Basic Concepts

### 1. What is SSL Pinning?
SSL Pinning ensures that an app only communicates with servers presenting specific SSL certificates or public keys, preventing:
- MITM attacks
- Certificate authority compromises
- Malicious proxy certificates

### 2. Types of SSL Pinning
1. Certificate Pinning
   - Pins the exact certificate
   - More restrictive
   - Requires updates when certificate changes

2. Public Key Pinning
   - Pins the public key
   - More flexible
   - Survives certificate renewals

## Implementation Methods

### 1. URLSession Pinning

#### Certificate Pinning
```swift
class CertificatePinningURLSession: NSObject, URLSessionDelegate {
    private let pinnedCertificateData: Data
    
    init(certificateFileName: String) {
        let certificatePath = Bundle.main.path(forResource: certificateFileName, ofType: "cer")!
        pinnedCertificateData = try! Data(contentsOf: URL(fileURLWithPath: certificatePath))
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
        
        // Get server certificate data
        let serverCertificateData = SecCertificateCopyData(certificate) as Data
        
        if serverCertificateData == pinnedCertificateData {
            completionHandler(.useCredential, URLCredential(trust: serverTrust))
        } else {
            completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }
}

// Usage
let session = URLSession(
    configuration: .default,
    delegate: CertificatePinningURLSession(certificateFileName: "server"),
    delegateQueue: nil
)
```

#### Public Key Pinning
```swift
class PublicKeyPinningURLSession: NSObject, URLSessionDelegate {
    private let pinnedPublicKey: SecKey
    
    init(publicKeyFileName: String) {
        let publicKeyPath = Bundle.main.path(forResource: publicKeyFileName, ofType: "der")!
        let publicKeyData = try! Data(contentsOf: URL(fileURLWithPath: publicKeyPath))
        
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic
        ]
        
        pinnedPublicKey = SecKeyCreateWithData(publicKeyData as CFData,
                                             attributes as CFDictionary,
                                             nil)!
        super.init()
    }
    
    func urlSession(_ session: URLSession,
                   didReceive challenge: URLAuthenticationChallenge,
                   completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        
        guard let serverTrust = challenge.protectionSpace.serverTrust,
              let certificate = SecTrustGetCertificateAtIndex(serverTrust, 0),
              let publicKey = SecCertificateCopyKey(certificate) else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        
        if publicKey == pinnedPublicKey {
            completionHandler(.useCredential, URLCredential(trust: serverTrust))
        } else {
            completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }
}
```

### 2. Alamofire Implementation

#### Certificate Pinning
```swift
class NetworkManager {
    static let shared = NetworkManager()
    
    private let session: Session
    
    private init() {
        let evaluators = [
            "api.example.com": PinnedCertificatesTrustEvaluator(certificates: [
                Certificates.api
            ])
        ]
        
        session = Session(
            serverTrustManager: ServerTrustManager(evaluators: evaluators)
        )
    }
    
    func request(_ url: URLConvertible,
                method: HTTPMethod = .get,
                parameters: Parameters? = nil) -> DataRequest {
        return session.request(
            url,
            method: method,
            parameters: parameters
        )
    }
}

// Usage
NetworkManager.shared.request("https://api.example.com/data")
    .responseDecodable(of: ResponseType.self) { response in
        switch response.result {
        case .success(let data):
            print("Success:", data)
        case .failure(let error):
            print("Error:", error)
        }
    }
```

#### Public Key Pinning
```swift
class PublicKeyPinningManager {
    static let shared = PublicKeyPinningManager()
    
    private let session: Session
    
    private init() {
        let evaluators = [
            "api.example.com": PublicKeysTrustEvaluator(
                keys: [
                    .init(publicKey: Certificates.apiPublicKey, httpMethod: nil, host: nil)
                ],
                performDefaultValidation: true,
                validateHost: true
            )
        ]
        
        session = Session(
            serverTrustManager: ServerTrustManager(evaluators: evaluators)
        )
    }
}
```

## Advanced Implementation

### 1. Multiple Certificate Support
```swift
class MultiCertificatePinning: NSObject, URLSessionDelegate {
    private let pinnedCertificates: [Data]
    
    init(certificateFileNames: [String]) {
        pinnedCertificates = certificateFileNames.compactMap { fileName in
            guard let path = Bundle.main.path(forResource: fileName, ofType: "cer"),
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

### 2. Certificate Chain Validation
```swift
class ChainValidationPinning: NSObject, URLSessionDelegate {
    private let pinnedIntermediateCertificates: [SecCertificate]
    
    init(intermediateCertificateNames: [String]) {
        pinnedIntermediateCertificates = intermediateCertificateNames.compactMap { name in
            guard let path = Bundle.main.path(forResource: name, ofType: "cer"),
                  let data = try? Data(contentsOf: URL(fileURLWithPath: path)),
                  let certificate = SecCertificateCreateWithData(nil, data as CFData) else {
                return nil
            }
            return certificate
        }
        super.init()
    }
    
    func urlSession(_ session: URLSession,
                   didReceive challenge: URLAuthenticationChallenge,
                   completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        
        guard let serverTrust = challenge.protectionSpace.serverTrust else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        
        // Get certificate chain
        var certificateChain: [SecCertificate] = []
        for i in 0..<SecTrustGetCertificateCount(serverTrust) {
            if let certificate = SecTrustGetCertificateAtIndex(serverTrust, i) {
                certificateChain.append(certificate)
            }
        }
        
        // Check intermediate certificates
        for pinnedCert in pinnedIntermediateCertificates {
            if !certificateChain.contains(where: { cert in
                SecCertificateEqual(cert, pinnedCert)
            }) {
                completionHandler(.cancelAuthenticationChallenge, nil)
                return
            }
        }
        
        completionHandler(.useCredential, URLCredential(trust: serverTrust))
    }
}
```

## Security Considerations

### 1. Certificate Management
```swift
class CertificateManager {
    static let shared = CertificateManager()
    
    private let certificateCache: NSCache<NSString, NSData>
    
    private init() {
        certificateCache = NSCache<NSString, NSData>()
    }
    
    func loadCertificate(named name: String) -> Data? {
        // Check cache
        if let cachedData = certificateCache.object(forKey: name as NSString) {
            return cachedData as Data
        }
        
        // Load from bundle
        guard let path = Bundle.main.path(forResource: name, ofType: "cer"),
              let data = try? Data(contentsOf: URL(fileURLWithPath: path)) else {
            return nil
        }
        
        // Cache certificate
        certificateCache.setObject(data as NSData, forKey: name as NSString)
        return data
    }
    
    func updateCertificate(named name: String, with data: Data) {
        // Update cache
        certificateCache.setObject(data as NSData, forKey: name as NSString)
        
        // Save to documents directory
        guard let documentsPath = FileManager.default.urls(for: .documentDirectory,
                                                         in: .userDomainMask).first else {
            return
        }
        
        let certificateURL = documentsPath.appendingPathComponent("\(name).cer")
        try? data.write(to: certificateURL)
    }
}
```

### 2. Error Handling
```swift
enum SSLPinningError: Error {
    case certificateNotFound
    case certificateValidationFailed
    case publicKeyExtractionFailed
    case chainValidationFailed
    
    var localizedDescription: String {
        switch self {
        case .certificateNotFound:
            return "SSL Pinning Error: Certificate not found in bundle"
        case .certificateValidationFailed:
            return "SSL Pinning Error: Certificate validation failed"
        case .publicKeyExtractionFailed:
            return "SSL Pinning Error: Failed to extract public key"
        case .chainValidationFailed:
            return "SSL Pinning Error: Certificate chain validation failed"
        }
    }
}

class SSLPinningErrorHandler {
    static func handle(_ error: SSLPinningError) {
        switch error {
        case .certificateNotFound:
            // Log error and notify user
            logError(error)
            showAlert(message: "Security Error: Unable to establish secure connection")
            
        case .certificateValidationFailed:
            // Log potential MITM attack
            logSecurityIncident(error)
            showAlert(message: "Security Warning: Connection may be compromised")
            
        case .publicKeyExtractionFailed:
            // Log technical error
            logError(error)
            showAlert(message: "Technical Error: Please try again later")
            
        case .chainValidationFailed:
            // Log chain validation failure
            logSecurityIncident(error)
            showAlert(message: "Security Error: Invalid certificate chain")
        }
    }
    
    private static func logError(_ error: Error) {
        // Implement secure logging
    }
    
    private static func logSecurityIncident(_ error: Error) {
        // Log security incident for analysis
    }
    
    private static func showAlert(message: String) {
        DispatchQueue.main.async {
            // Show alert to user
        }
    }
}
```

## Documentation Template
```markdown
# SSL Pinning Implementation Report

## Certificate Details
- Subject:
- Issuer:
- Valid Until:
- Key Algorithm:

## Implementation
### Pinning Method
- [ ] Certificate Pinning
- [ ] Public Key Pinning
- [ ] Chain Validation

### Security Measures
- [ ] Certificate rotation
- [ ] Error handling
- [ ] Logging
- [ ] User notifications

## Testing Results
### Test Cases
1. Valid Certificate:
   - Expected:
   - Result:

2. Invalid Certificate:
   - Expected:
   - Result:

### Security Tests
1. MITM Attack:
   - Method:
   - Result:
   - Protection:
```

## Best Practices

### 1. Implementation Guidelines
- Use multiple certificates
- Implement certificate rotation
- Add comprehensive logging
- Handle errors gracefully
- Monitor for security incidents

### 2. Security Measures
- Protect certificate storage
- Implement backup validation
- Monitor certificate expiry
- Update certificates securely
- Log security events

## Troubleshooting Guide

### Common Issues
1. Certificate Mismatch
   - Check bundle resources
   - Verify certificate format
   - Update expired certificates

2. Connection Failures
   - Validate server certificate
   - Check implementation
   - Debug chain validation

## Resources
1. Apple Security Documentation
2. SSL/TLS Standards
3. Security Tools
4. Developer Forums
