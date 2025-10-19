# Digital Forensics Agent System (DFAS)

A BDI-inspired multi-agent system for automated digital forensics evidence collection, processing, and packaging.  

---

## Table of Contents
1. [Overview](#overview)  
2. [Features](#features)  
3. [Architecture](#architecture)  
4. [Installation](#installation)  
5. [Configuration](#configuration)  
6. [Usage](#usage)  
7. [Output Files](#output-files)  
8. [Testing](#testing)  
9. [Technical Details](#technical-details)  
10. [Compliance](#compliance)  
11. [Troubleshooting](#troubleshooting)  
12. [Academic References](#academic-references)  
13. [Support](#support)  

---

##  Overview
DFAS is a professional-grade digital forensics tool designed for **automated evidence collection** and **standards-compliant processing**.  
It is built using **Belief-Desire-Intention (BDI) multi-agent principles**, ensuring robust, auditable, and scalable forensic workflows.

**Objectives:**
- Automated evidence discovery and metadata extraction  
- Compliance with ISO/IEC 27037, NIST SP 800-86, ACPO guidelines  
- Tamper-proof chain of custody  
- SHA-256 integrity hashing  
- AES-GCM encrypted evidence packaging  

---

##  Features
-  **Intelligent File Discovery** with configurable filters  
-  **SHA-256 Hashing** for integrity verification  
-  **Metadata Extraction** (size, timestamps, ownership)  
-  **File Type Detection** using `libmagic` with fallback to `mimetypes`  
-  **Encrypted Packaging** with AES-GCM  
-  **Multi-format Reports** (CSV, JSON, SQLite)  
-  **Chain of Custody Logging** with cryptographic sealing  

---

##  Architecture
![alt text](image.png)
## 🚀 Installation

### Prerequisites
- Python **3.11+**  
- OS: Windows 10/11, Ubuntu 22.04+, macOS 13+  

### Quick Setup
```bash
# Clone/download the repo
# create the folder named DFAS and paste the files
cd DFAS

# Run automated setup
python setup.py
```

### Manual Installation
```bash
pip install -r requirements.txt
```

### Optional (Enhanced File Type Detection)
- **Windows:** `pip install python-magic-bin`  
- **Linux:** `sudo apt-get install libmagic1 && pip install python-magic`  
- **macOS:** `brew install libmagic && pip install python-magic`  

---

##  Configuration
On first run, DFAS generates `dfas_config.yaml`. Example:
```yaml
case_id: "case-2024-001"
collected_by: "investigator@organization"

scan_paths:
  - "."
  - "/path/to/evidence"

exclude_paths:
  - "__pycache__"
  - ".git"

target_extensions:
  - ".pdf"
  - ".docx"
  - ".xlsx"
  - ".txt"
  - ".jpg"
  - ".png"
  - ".zip"

max_file_size: 104857600  # 100MB
output_dir: "./evidence_packages"
```

---

##  Usage
Basic run:
```bash
python DFAS.py
```

Execution flow:
1. **Initialization** → load config, start agents  
2. **Discovery Phase** → scan files  
3. **Processing Phase** → hash & extract metadata  
4. **Packaging Phase** → create encrypted evidence package  
5. **Summary Report** → outputs logs and package info  

---

##  Output Files
- `evidence_[case_id].db` → SQLite database (records + custody)  
- `evidence_report_[case_id].csv` → CSV evidence listing  
- `evidence_report_[case_id].json` → JSON evidence records  
- `evidence_package_[case_id].zip` → Encrypted evidence bundle  
- `dfas.log` → Execution logs  

---

##  Testing
Run built-in validation:
```bash
python -c "
import DFAS
config = DFAS.load_config()
print('✓ Config loaded')
db = DFAS.DatabaseManager('test.db')
print('✓ Database initialized')
"
```

Create test files:
```bash
echo "Test document" > test_document.txt
python DFAS.py
```

Checklist:
- [x] Config created  
- [x] Database initialized  
- [x] Discovery working  
- [x] Hashing functional  
- [x] Reports generated  
- [x] Encrypted package created  

---

##  Technical Details
- **Cryptography:** SHA-256 (FIPS 180-4), AES-GCM encryption  
- **Performance:** Multithreading, queue-based architecture  
- **File Typing:** `libmagic` > `mimetypes` > manual extension map  

---

##  Compliance
Implements standards from:
- **ISO/IEC 27037, 27041, 27042, 27043**  
- **NIST SP 800-86, FIPS 180-4**  
- **ACPO Principles (2012)**  

---

##  Troubleshooting
- **libmagic ImportError** → install `python-magic` or fallback to `mimetypes`  
- **Permission denied** → run as Administrator / `sudo`  
- **High memory usage** → reduce `max_file_size` in config  

Enable debug logging in `DFAS.py`:
```python
logging.basicConfig(level=logging.DEBUG)
```

---

##  Academic References
- Rao & Georgeff (1995) *BDI Agents: From Theory to Practice*  
- Wooldridge (2009) *MultiAgent Systems*  
- ISO/IEC (2012) *27037: Guidelines for Digital Evidence*  
- NIST (2006) *SP 800-86: Forensic Techniques*  

---

##  Support
- Check logs in `dfas.log`  
- Verify configuration in `dfas_config.yaml`  
- Test with sample files  
