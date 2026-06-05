#!/usr/bin/env python3
"""
Repository Security Scanner
Scans GitHub repositories for malicious and suspicious code patterns
"""

import os
import json
import sys
import argparse
from pathlib import Path
from threat_patterns import extract_threats, THREAT_PATTERNS
from report_generator import generate_html_report, generate_json_report
from colorama import Fore, Style, init

init(autoreset=True)

# File extensions to scan
SCANNABLE_EXTENSIONS = {
    '.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.cpp', '.c', '.go', 
    '.rb', '.php', '.sh', '.bash', '.json', '.yaml', '.yml', '.html'
}

# Files to skip
SKIP_PATTERNS = {
    'node_modules', '.git', 'dist', 'build', '.venv', 'venv',
    '__pycache__', '.egg-info', 'vendor', '.next', 'out'
}

def is_scannable_file(filepath):
    """Check if file should be scanned"""
    path = Path(filepath)
    
    # Skip directories
    if path.is_dir():
        return False
    
    # Skip large files (> 1MB)
    try:
        if path.stat().st_size > 1024 * 1024:
            return False
    except:
        return False
    
    # Skip binary files
    if path.suffix in {'.pyc', '.o', '.so', '.dll', '.exe', '.png', '.jpg', '.gif'}:
        return False
    
    # Check if it's in skip directories
    for skip in SKIP_PATTERNS:
        if skip in path.parts:
            return False
    # Skip the scanner tool itself
    if any(skip in str(filepath) for skip in ['scanner.py', 'threat_patterns.py', 'report_generator.py', '.github']):
        return False
    
    return path.suffix in SCANNABLE_EXTENSIONS or path.suffix == ''

def scan_directory(directory):
    """Scan all files in directory recursively"""
    all_threats = []
    scanned_files = 0
    
    print(f"\n{Fore.CYAN}{'='*100}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}🔍 Repository Security Scanner - Analyzing Repository{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*100}{Style.RESET_ALL}")
    print(f"{Fore.WHITE}📁 Scanning: {directory}{Style.RESET_ALL}\n")
    
    for root, dirs, files in os.walk(directory):
        # Filter skip directories
        dirs[:] = [d for d in dirs if d not in SKIP_PATTERNS]
        
        for file in files:
            filepath = os.path.join(root, file)
            
            if not is_scannable_file(filepath):
                continue
            
            scanned_files += 1
            relative_path = os.path.relpath(filepath, directory)
            
            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                threats = extract_threats(content, relative_path)
                if threats:
                    all_threats.extend(threats)
                    print(f"{Fore.YELLOW}⚠️  {relative_path}: {len(threats)} threat(s) found{Style.RESET_ALL}")
            
            except Exception as e:
                pass
    
    return all_threats, scanned_files

def print_threats_summary(threats):
    """Print threats summary to console with detailed information"""
    if not threats:
        print(f"\n{Fore.GREEN}{'='*100}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}✅ SECURITY STATUS: SAFE{Style.RESET_ALL}")
        print(f"{Fore.GREEN}{'='*100}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}No malicious or suspicious threats detected!{Style.RESET_ALL}")
        print(f"{Fore.GREEN}Repository appears safe to use.{Style.RESET_ALL}\n")
        return
    
    # Sort by severity
    severity_order = {"🔴 CRITICAL": 0, "🟠 HIGH": 1, "🟡 MEDIUM": 2}
    threats_sorted = sorted(threats, key=lambda x: severity_order.get(x["severity"], 3))
    
    print(f"\n{Fore.RED}{'='*100}{Style.RESET_ALL}")
    print(f"{Fore.RED}🚨 SECURITY STATUS: CRITICAL - {len(threats)} THREAT(S) DETECTED{Style.RESET_ALL}")
    print(f"{Fore.RED}{'='*100}{Style.RESET_ALL}\n")
    
    current_category = None
    threat_number = 1
    
    for threat in threats_sorted:
        if threat["category"] != current_category:
            current_category = threat["category"]
            print(f"\n{Fore.RED}{'─'*100}{Style.RESET_ALL}")
            print(f"{Fore.RED}{threat['severity']} │ {threat['category'].upper()}{Style.RESET_ALL}")
            print(f"{Fore.RED}{'─'*100}{Style.RESET_ALL}")
        
        print(f"\n{Fore.WHITE}[THREAT #{threat_number}]{Style.RESET_ALL}")
        print(f"{Fore.CYAN}📍 Location:{Style.RESET_ALL} {Fore.YELLOW}{threat['file']}{Style.RESET_ALL}:{Fore.YELLOW}{threat['line']}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}🔴 Type:{Style.RESET_ALL} {threat['threat_name']}")
        print(f"{Fore.CYAN}📝 What it does:{Style.RESET_ALL} {threat['description']}")
        print(f"{Fore.CYAN}💻 Code detected:{Style.RESET_ALL}")
        print(f"    {Fore.RED}{threat['line_content'][:120]}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}🎯 Pattern matched:{Style.RESET_ALL} {Fore.RED}{threat['matched_text'][:100]}{Style.RESET_ALL}")
        
        threat_number += 1

def calculate_risk_score(threats):
    """Calculate overall risk score"""
    if not threats:
        return "🟢 SAFE", 0
    
    critical_count = sum(1 for t in threats if "CRITICAL" in t["severity"])
    high_count = sum(1 for t in threats if "HIGH" in t["severity"])
    medium_count = sum(1 for t in threats if "MEDIUM" in t["severity"])
    
    score = (critical_count * 100) + (high_count * 50) + (medium_count * 20)
    
    if score >= 100:
        return "🔴 CRITICAL", score
    elif score >= 50:
        return "🟠 HIGH RISK", score
    elif score >= 20:
        return "🟡 MEDIUM RISK", score
    else:
        return "🟢 LOW RISK", score

def main():
    parser = argparse.ArgumentParser(
        description="Repository Security Scanner - Detect malicious code patterns",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("path", help="Path to repository or directory to scan")
    parser.add_argument("--json", action="store_true", help="Output as JSON only")
    parser.add_argument("--html", action="store_true", help="Generate HTML report")
    parser.add_argument("--output", "-o", help="Output file path")
    
    args = parser.parse_args()
    
    if not os.path.exists(args.path):
        print(f"{Fore.RED}❌ Path not found: {args.path}{Style.RESET_ALL}")
        sys.exit(1)
    
    # Scan the directory
    threats, scanned_files = scan_directory(args.path)
    
    print(f"{Fore.CYAN}{'─'*100}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}📊 Scan Complete: {scanned_files} files scanned{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'─'*100}{Style.RESET_ALL}")
    
    # Print summary
    print_threats_summary(threats)
    
    # Calculate risk score
    risk_level, score = calculate_risk_score(threats)
    
    print(f"\n{Fore.CYAN}{'='*100}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}📈 FINAL RISK ASSESSMENT{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*100}{Style.RESET_ALL}")
    
    if score >= 100:
        print(f"{Fore.RED}{risk_level} ({score}/1000){Style.RESET_ALL}")
        print(f"{Fore.RED}⛔ DO NOT USE THIS REPOSITORY - Contains serious security threats{Style.RESET_ALL}")
    else:
        print(f"{Fore.GREEN}{risk_level} ({score}/1000){Style.RESET_ALL}")
        print(f"{Fore.GREEN}✅ SAFE - Repository appears secure to use{Style.RESET_ALL}")
    
    print(f"{Fore.CYAN}{'='*100}{Style.RESET_ALL}\n")
    
    # Generate reports
    if args.json or args.output:
        json_report = generate_json_report(threats, args.path, scanned_files, risk_level, score)
        output_file = args.output or "report.json"
        with open(output_file, 'w') as f:
            json.dump(json_report, f, indent=2)
        print(f"{Fore.GREEN}✅ JSON report saved: {output_file}{Style.RESET_ALL}")
    
    if args.html or (not args.json and args.output and args.output.endswith('.html')):
        html_report = generate_html_report(threats, args.path, scanned_files, risk_level, score)
        output_file = args.output or "report.html"
        with open(output_file, 'w') as f:
            f.write(html_report)
        print(f"{Fore.GREEN}✅ HTML report saved: {output_file}{Style.RESET_ALL}")
    
    # Exit with appropriate code
    sys.exit(0 if not threats else 1)

if __name__ == "__main__":
    main()
