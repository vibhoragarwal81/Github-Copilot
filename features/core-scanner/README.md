# Core Scanner Feature - IAMCloud

This feature contains the core scanning engine and business logic for IAMCloud security posture management.

## 📁 Structure

```
features/core-scanner/
├── scanners/               # Core scanning modules
├── rules/                 # Security rules and policies
├── reports/               # Report generation
├── utils/                 # Utility functions
├── main.py               # Main scanner entry point
└── README.md             # This file
```

## 🔧 Core Components

- **Scanners**: AWS service-specific scanning logic
- **Rules Engine**: Security rules and compliance checks
- **Report Generator**: HTML, JSON, CSV output generation
- **AWS Integration**: Multi-account and organization scanning

## 🚀 Usage

The core scanner can be used by:
- CLI tool for local scanning
- GitHub Actions for automated scanning
- Integration with other IAMCloud features

See the main project README for detailed usage instructions.