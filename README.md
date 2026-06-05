![Security Scan](https://github.com/PKB12022/repo-security-scanner/actions/workflows/security-scan.yml/badge.svg)
# Repository Security Scanner 🔍

A comprehensive security scanner that detects suspicious and malicious code patterns in downloaded GitHub repositories, protecting users from privacy violations and security threats.

## Features

🚨 **Threat Detection:**
- **Suspicious Data Collection** - Detects code that exfiltrates user data
- **Malicious Dependencies** - Identifies harmful packages and versions
- **Arbitrary Code Execution (ACE)** - Finds code executing untrusted input
- **Remote Code Download & Execution** - Detects dynamic code loading
- **Cryptocurrency Mining** - Identifies xmrig, monero, mining pools, CPU loops
- **Webcam/Microphone Access** - Detects unauthorized hardware access
- **Screen Capture** - Identifies screen recording/capture attempts

## Risk Levels

- 🔴 **Critical** - Cryptocurrency mining, ACE, webcam/mic access
- 🟠 **High** - Remote code execution, suspicious data collection
- 🟡 **Medium** - Malicious dependencies, unusual patterns
- 🟢 **Safe** - No threats detected

## Output

Each finding includes:
- **Location**: File path and line number(s)
- **Threat Type**: Category of the threat
- **Severity**: Risk level
- **Description**: What the code does and why it's dangerous
- **Code Snippet**: The actual suspicious code

## Installation

```bash
git clone https://github.com/PKB12022/repo-security-scanner.git
cd repo-security-scanner
pip install -r requirements.txt
```

## Usage

```bash
python scanner.py /path/to/repository
```

Or scan a GitHub repository directly:

```bash
python scanner.py --github username/repository
```

## Output

Results are displayed in the terminal and saved as:
- `report.json` - Machine-readable format
- `report.html` - Interactive HTML report

## Example Report

```
CRITICAL 🔴 - Cryptocurrency Mining
Location: src/worker.js:142-156
Description: xmrig mining script detected - unauthorized CPU usage
Code: var miner = new CoinHive('pool.minexmr.com', 'wallet_address')
```

## Contributing

Contributions welcome! Add detection patterns for new threat types.

## License

MIT License
