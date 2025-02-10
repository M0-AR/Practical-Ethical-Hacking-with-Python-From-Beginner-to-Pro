# Basic APK Analysis

## Introduction
This section covers fundamental APK analysis techniques, focusing on understanding the basic structure and components of Android applications.

## Learning Objectives
1. Understand APK file structure
2. Extract and analyze APK contents
3. Read and interpret AndroidManifest.xml
4. Identify basic app components

## APK Structure Analysis

### 1. APK Components
- **META-INF/**
  - Contains metadata about the APK
  - Signature files
  - Manifest file

- **lib/**
  - Native libraries (.so files)
  - Architecture-specific code

- **res/**
  - Resource files
  - Layouts
  - Images
  - String resources

- **AndroidManifest.xml**
  - App configuration
  - Permissions
  - Components declaration

- **classes.dex**
  - Compiled application code
  - Dalvik executable format

- **resources.arsc**
  - Compiled resources
  - Resource mapping

## Practical Exercises

### Exercise 1: APK Extraction
```bash
# Extract APK contents
apktool d sample.apk -o output_folder

# Examine structure
cd output_folder
ls -la
```

### Exercise 2: Manifest Analysis
1. Locate AndroidManifest.xml
2. Identify:
   - Package name
   - Permissions
   - Activities
   - Services
   - Receivers

### Exercise 3: Resource Analysis
1. Examine res/ directory
2. Identify:
   - Layout files
   - String resources
   - Image assets
   - Configuration files

## Tools Required
1. **APKTool**
   - Purpose: APK decompilation
   - Installation: `apt-get install apktool`

2. **ADB (Android Debug Bridge)**
   - Purpose: Device communication
   - Installation: Part of Android SDK

3. **File Viewer**
   - Purpose: Examine extracted files
   - Example: VS Code, Sublime Text

## Analysis Checklist
- [ ] Extract APK contents
- [ ] Review manifest file
- [ ] List all permissions
- [ ] Identify main activity
- [ ] Check resource files
- [ ] Document findings

## Common Findings
1. **Excessive Permissions**
   - What to look for
   - Why it's important
   - How to document

2. **Insecure Configurations**
   - Debug flags
   - Backup settings
   - Security attributes

3. **Hardcoded Values**
   - API endpoints
   - Credentials
   - Security tokens

## Documentation Template
```markdown
# APK Analysis Report

## Basic Information
- Package Name:
- Version:
- Min SDK:
- Target SDK:

## Permissions
1. Permission 1
   - Purpose:
   - Risk Level:
2. Permission 2
   - Purpose:
   - Risk Level:

## Components
1. Activities
2. Services
3. Receivers
4. Providers

## Resources
1. Important Files
2. Sensitive Data
3. Configuration Issues

## Recommendations
1. Security Improvements
2. Best Practices
3. Risk Mitigation
```

## Next Steps
1. Move to intermediate analysis
2. Learn decompilation techniques
3. Start dynamic analysis
4. Practice with real apps

## Resources
1. Official Android Documentation
2. OWASP Mobile Testing Guide
3. Android Security Guidelines
4. Community Forums
