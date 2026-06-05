"""
Threat Pattern Definitions for Repository Security Scanner
Contains regex patterns and keywords for detecting malicious/suspicious code
"""

import re

THREAT_PATTERNS = {
    # ============ CRYPTOCURRENCY MINING ============
    "cryptocurrency_mining": {
        "severity": "🔴 CRITICAL",
        "category": "Cryptocurrency Mining",
        "patterns": [
            {
                "name": "XMRig Mining",
                "pattern": r"xmrig|CoinHive|coinhive",
                "description": "XMRig or CoinHive cryptocurrency miner detected - unauthorized CPU usage for Monero mining"
            },
            {
                "name": "Mining Pool Connection",
                "pattern": r"(pool\.minexmr\.com|pool\.supportxmr\.com|moneropool|mining\.pool|stratum\+tcp)",
                "description": "Connection to cryptocurrency mining pool detected - enables remote mining operations"
            },
            {
                "name": "CPU Intensive Loop",
                "pattern": r"while\s*\(\s*true\s*\)\s*{[^}]{0,500}(Math\.sqrt|cpu|loop|hash|nonce)",
                "description": "Infinite CPU-intensive loop detected - potential mining or resource exhaustion"
            },
            {
                "name": "Worker Pool Mining",
                "pattern": r"worker|thread|spawn.*mine|hashrate|difficulty",
                "description": "Worker/thread-based mining infrastructure detected"
            }
        ]
    },

    # ============ ARBITRARY CODE EXECUTION (ACE) ============
    "arbitrary_code_execution": {
        "severity": "🔴 CRITICAL",
        "category": "Arbitrary Code Execution",
        "patterns": [
            {
                "name": "Eval with User Input",
                "pattern": r"eval\s*\(\s*(?:process\.argv|process\.env|req\.|input\(|raw_input|sys\.argv|__import__)",
                "description": "eval() or similar executing user-controlled/environment data - enables code injection"
            },
            {
                "name": "Function Constructor",
                "pattern": r"new\s+Function\s*\(|Function\s*\(\s*(?:process\.|__)",
                "description": "Dynamic function creation from user input - potential code execution vulnerability"
            },
            {
                "name": "Shell Command Injection",
                "pattern": r"exec\s*\(|system\s*\(|os\.popen|subprocess|shell=True",
                "description": "Shell command execution with user input - command injection risk"
            },
            {
                "name": "Template Injection",
                "pattern": r"render_template|jinja2\.Template\(.*request|template\.render\(.*input",
                "description": "Template rendering with user input - SSTI vulnerability"
            }
        ]
    },

    # ============ REMOTE CODE DOWNLOAD & EXECUTION ============
    "remote_code_execution": {
        "severity": "🔴 CRITICAL",
        "category": "Remote Code Download & Execution",
        "patterns": [
            {
                "name": "Script Download & Execute",
                "pattern": r"fetch\(.*\)\.then\(.*\.text\(\)\)\.then\(eval|urllib\.request\.urlopen.*exec|requests\.get.*exec|curl.*python|wget.*python",
                "description": "Downloads and executes code from remote URL - complete code injection"
            },
            {
                "name": "Dynamic Import/Require",
                "pattern": r"require\(.*process\.|__import__\(.*\+|dynamic.*import|importlib\.import_module\(.*\+",
                "description": "Dynamically imports modules from user-controlled paths - RCE vector"
            },
            {
                "name": "Child Process with Remote Code",
                "pattern": r"spawn|fork|exec.*http|execFile.*fetch|\.sh.*curl",
                "description": "Spawns child process executing remote code - enables privilege escalation"
            },
            {
                "name": "Package Installation from URL",
                "pattern": r"pip\s+install.*http|npm\s+install.*http|yarn\s+add.*http",
                "description": "Installs packages from remote URLs - supply chain attack vector"
            }
        ]
    },

    # ============ SUSPICIOUS DATA COLLECTION ============
    "data_collection": {
        "severity": "🟠 HIGH",
        "category": "Suspicious Data Collection",
        "patterns": [
            {
                "name": "Exfiltrate to External Server",
                "pattern": r"fetch\(|requests\.post|http\.post|XMLHttpRequest|axios\.post|\.send\(.*http",
                "description": "Sends data to external server/URL - potential data exfiltration"
            },
            {
                "name": "Keystroke Logging",
                "pattern": r"onkeypress|onkeydown|addEventListener.*key|keyLogger|captureKeys",
                "description": "Keystroke capturing code detected - logs user input for theft"
            },
            {
                "name": "Clipboard Access",
                "pattern": r"navigator\.clipboard|document\.execCommand.*copy|getSelection|ClipboardData",
                "description": "Clipboard access detected - can steal sensitive data user copied"
            },
            {
                "name": "Browser History Access",
                "pattern": r"history\.go|sessionStorage|localStorage.*password|document\.referrer|location\.href.*exfil",
                "description": "Accesses browser history/storage - collects browsing behavior"
            },
            {
                "name": "Geolocation Tracking",
                "pattern": r"navigator\.geolocation|getCurrentPosition|watchPosition|latitude.*longitude",
                "description": "Geolocation tracking enabled - reveals user location"
            },
            {
                "name": "User Agent & Device Fingerprinting",
                "pattern": r"navigator\.userAgent.*post|canvas.*fingerprint|webgl.*vendor|device.*signature",
                "description": "Collects device/browser fingerprint - tracks users across sites"
            }
        ]
    },

    # ============ MALICIOUS DEPENDENCIES ============
    "malicious_dependencies": {
        "severity": "🟠 HIGH",
        "category": "Malicious Dependencies",
        "patterns": [
            {
                "name": "Typosquat Packages",
                "pattern": r"(expresss|nodemailer-sendgrid|cross-env|bcrypts|uuid-generator|angular-cli-ghpages|express-rate-limiter)",
                "description": "Typosquat package detected - legitimate package name misspelled to trick developers"
            },
            {
                "name": "Suspicious Package Installation",
                "pattern": r"npm install.*--registry\s+http|pip install.*--index-url\s+http|yarn config set registry http",
                "description": "Uses custom/insecure package registry - risk of malicious packages"
            },
            {
                "name": "Post-install Hook Execution",
                "pattern": r'"postinstall":\s*".*exec|"preinstall":\s*".*curl|"scripts":\s*{[^}]*"postinstall":\s*"[^"]*\$|scripts.*\.sh',
                "description": "Post-install scripts run automatically - can execute malicious code on install"
            },
            {
                "name": "Obfuscated Dependency",
                "pattern": r"_[a-zA-Z0-9]{20,}|require\(.*Buffer\.from.*base64|atob\(",
                "description": "Obfuscated or base64-encoded code detected - hides malicious functionality"
            }
        ]
    },

    # ============ WEBCAM & MICROPHONE ACCESS ============
    "hardware_access_camera": {
        "severity": "🔴 CRITICAL",
        "category": "Webcam/Microphone Access",
        "patterns": [
            {
                "name": "Webcam Access",
                "pattern": r"getUserMedia.*video|mediaDevices\.getUserMedia|camera|webcam",
                "description": "Requests access to user's webcam - can capture video without consent"
            },
            {
                "name": "Microphone Access",
                "pattern": r"getUserMedia.*audio|mediaDevices\.getUserMedia.*audio|microphone|mic",
                "description": "Requests access to microphone - enables audio recording/eavesdropping"
            },
            {
                "name": "Hardware Permission Prompt",
                "pattern": r"requestPermission|android\.permission\.CAMERA|android\.permission\.RECORD_AUDIO|kCMMediaTypeVideo",
                "description": "Requests hardware permissions - may be hiding intent to use camera/mic"
            },
            {
                "name": "MediaRecorder Setup",
                "pattern": r"MediaRecorder|webkitMediaStream|mozMediaStream",
                "description": "MediaRecorder configured - enables audio/video recording"
            }
        ]
    },

    # ============ SCREEN CAPTURE ============
    "screen_capture": {
        "severity": "🔴 CRITICAL",
        "category": "Screen Capture",
        "patterns": [
            {
                "name": "Screen Capture API",
                "pattern": r"getDisplayMedia|captureStream|mozGetUserMedia.*display|screen.*capture|screenshot",
                "description": "Screen capture enabled - can record everything user sees including sensitive data"
            },
            {
                "name": "Canvas Screenshot",
                "pattern": r"canvas\.toDataURL|canvas\.toBlob|canvaselement.*screenshot|drawImage.*canvas",
                "description": "Canvas rendering to image - can capture rendered content as screenshot"
            },
            {
                "name": "Virtual Display Monitoring",
                "pattern": r"DisplayMetrics|WindowManager.*getDefaultDisplay|screenCapture|framebuffer",
                "description": "Virtual display/framebuffer access - monitors screen content"
            }
        ]
    }
}

def extract_threats(content, filename):
    """
    Extract all threats from file content
    Returns list of found threats with details
    """
    threats = []
    
    for threat_category, threat_info in THREAT_PATTERNS.items():
        for pattern_def in threat_info["patterns"]:
            matches = re.finditer(pattern_def["pattern"], content, re.IGNORECASE | re.MULTILINE)
            
            for match in matches:
                # Find line number
                line_num = content[:match.start()].count('\n') + 1
                
                # Get line content
                lines = content.split('\n')
                line_content = lines[line_num - 1] if line_num <= len(lines) else ""
                
                threats.append({
                    "file": filename,
                    "line": line_num,
                    "severity": threat_info["severity"],
                    "category": threat_info["category"],
                    "threat_name": pattern_def["name"],
                    "description": pattern_def["description"],
                    "matched_text": match.group(0),
                    "line_content": line_content.strip()
                })
    
    return threats
