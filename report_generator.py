"""
Report Generator - Creates JSON and HTML security reports
"""

import json
from datetime import datetime

def generate_json_report(threats, repo_path, scanned_files, risk_level, risk_score):
    """Generate JSON formatted security report"""
    
    return {
        "scan_metadata": {
            "timestamp": datetime.now().isoformat(),
            "repository_path": repo_path,
            "files_scanned": scanned_files,
            "threats_found": len(threats)
        },
        "risk_assessment": {
            "overall_risk": risk_level,
            "risk_score": risk_score,
            "recommendation": get_recommendation(risk_score)
        },
        "threat_summary": {
            "critical": len([t for t in threats if "CRITICAL" in t["severity"]]),
            "high": len([t for t in threats if "HIGH" in t["severity"]]),
            "medium": len([t for t in threats if "MEDIUM" in t["severity"]]),
            "low": len([t for t in threats if "LOW" in t["severity"]])
        },
        "threats": threats
    }

def generate_html_report(threats, repo_path, scanned_files, risk_level, risk_score):
    """Generate HTML formatted security report"""
    
    # Group threats by category
    categories = {}
    for threat in threats:
        cat = threat["category"]
        if cat not in categories:
            categories[cat] = []
        categories[cat].append(threat)
    
    # Build threat rows HTML
    threat_rows = ""
    for threat in threats:
        severity_color = {
            "🔴 CRITICAL": "#d32f2f",
            "🟠 HIGH": "#f57c00",
            "🟡 MEDIUM": "#fbc02d",
            "🟢 LOW": "#388e3c"
        }.get(threat["severity"], "#999")
        
        threat_rows += f"""
        <tr>
            <td><span style="color: {severity_color}; font-weight: bold;">{threat['severity']}</span></td>
            <td>{threat['category']}</td>
            <td>{threat['threat_name']}</td>
            <td><code>{threat['file']}</code>:{threat['line']}</td>
            <td>{threat['description']}</td>
            <td><code style="background: #f5f5f5; padding: 2px 4px; border-radius: 3px;">{threat['matched_text'][:50]}...</code></td>
        </tr>
        """
    
    # Recommendation color
    if risk_score >= 100:
        badge_color = "#d32f2f"
        action_class = "danger"
    elif risk_score >= 50:
        badge_color = "#f57c00"
        action_class = "warning"
    elif risk_score >= 20:
        badge_color = "#fbc02d"
        action_class = "info"
    else:
        badge_color = "#388e3c"
        action_class = "success"
    
    html = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Repository Security Scan Report</title>
        <style>
            * {{ margin: 0; padding: 0; box-sizing: border-box; }}
            body {{
                font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: #333;
                padding: 20px;
            }}
            .container {{
                max-width: 1200px;
                margin: 0 auto;
                background: white;
                border-radius: 10px;
                box-shadow: 0 10px 40px rgba(0,0,0,0.2);
                overflow: hidden;
            }}
            .header {{
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                padding: 40px;
                text-align: center;
            }}
            .header h1 {{
                font-size: 2.5em;
                margin-bottom: 10px;
            }}
            .header p {{
                font-size: 1.1em;
                opacity: 0.9;
            }}
            .content {{
                padding: 40px;
            }}
            .section {{
                margin-bottom: 40px;
            }}
            .section h2 {{
                font-size: 1.8em;
                margin-bottom: 20px;
                color: #667eea;
                border-bottom: 2px solid #667eea;
                padding-bottom: 10px;
            }}
            .risk-badge {{
                display: inline-block;
                background: {badge_color};
                color: white;
                padding: 15px 30px;
                border-radius: 5px;
                font-size: 1.3em;
                font-weight: bold;
                margin: 20px 0;
            }}
            .stats {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                gap: 20px;
                margin: 20px 0;
            }}
            .stat-card {{
                background: #f5f5f5;
                padding: 20px;
                border-radius: 8px;
                text-align: center;
                border-left: 4px solid #667eea;
            }}
            .stat-card .number {{
                font-size: 2.5em;
                font-weight: bold;
                color: #667eea;
            }}
            .stat-card .label {{
                color: #666;
                margin-top: 10px;
            }}
            .threat-table {{
                width: 100%;
                border-collapse: collapse;
                margin-top: 20px;
                overflow-x: auto;
            }}
            .threat-table thead {{
                background: #f5f5f5;
            }}
            .threat-table th {{
                padding: 15px;
                text-align: left;
                font-weight: 600;
                color: #333;
                border-bottom: 2px solid #ddd;
            }}
            .threat-table td {{
                padding: 15px;
                border-bottom: 1px solid #eee;
            }}
            .threat-table tr:hover {{
                background: #f9f9f9;
            }}
            .severity-critical {{
                background: #ffebee;
                border-left: 4px solid #d32f2f;
            }}
            .severity-high {{
                background: #fff3e0;
                border-left: 4px solid #f57c00;
            }}
            .severity-medium {{
                background: #fffde7;
                border-left: 4px solid #fbc02d;
            }}
            .severity-low {{
                background: #e8f5e9;
                border-left: 4px solid #388e3c;
            }}
            .recommendation {{
                background: #e3f2fd;
                border-left: 4px solid #2196f3;
                padding: 20px;
                border-radius: 5px;
                margin: 20px 0;
            }}
            .recommendation h3 {{
                color: #1976d2;
                margin-bottom: 10px;
            }}
            .footer {{
                background: #f5f5f5;
                padding: 20px;
                text-align: center;
                color: #666;
                font-size: 0.9em;
            }}
            code {{
                background: #f5f5f5;
                padding: 2px 6px;
                border-radius: 3px;
                font-family: 'Courier New', monospace;
            }}
            .action-{action_class} {{
                background: {badge_color};
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🔍 Repository Security Scan Report</h1>
                <p>Comprehensive security analysis and threat detection</p>
            </div>
            
            <div class="content">
                <!-- Risk Assessment Section -->
                <div class="section">
                    <h2>⚠️ Risk Assessment</h2>
                    <div class="risk-badge action-{action_class}">
                        {risk_level}
                    </div>
                    <p><strong>Risk Score:</strong> {risk_score}/1000</p>
                    <p><strong>Repository:</strong> {repo_path}</p>
                    <p><strong>Files Scanned:</strong> {scanned_files}</p>
                    <p><strong>Threats Found:</strong> {len(threats)}</p>
                </div>
                
                <!-- Threat Statistics -->
                <div class="section">
                    <h2>📊 Threat Statistics</h2>
                    <div class="stats">
                        <div class="stat-card">
                            <div class="number" style="color: #d32f2f;">
                                {len([t for t in threats if "CRITICAL" in t["severity"]])}
                            </div>
                            <div class="label">🔴 Critical</div>
                        </div>
                        <div class="stat-card">
                            <div class="number" style="color: #f57c00;">
                                {len([t for t in threats if "HIGH" in t["severity"]])}
                            </div>
                            <div class="label">🟠 High</div>
                        </div>
                        <div class="stat-card">
                            <div class="number" style="color: #fbc02d;">
                                {len([t for t in threats if "MEDIUM" in t["severity"]])}
                            </div>
                            <div class="label">🟡 Medium</div>
                        </div>
                        <div class="stat-card">
                            <div class="number" style="color: #388e3c;">
                                {len([t for t in threats if "LOW" in t["severity"]])}
                            </div>
                            <div class="label">🟢 Low</div>
                        </div>
                    </div>
                </div>
                
                <!-- Recommendation -->
                <div class="recommendation">
                    <h3>📋 Recommendation</h3>
                    <p>{get_recommendation(risk_score)}</p>
                </div>
                
                <!-- Detailed Threats -->
                {'<div class="section"><h2>🚨 Detected Threats</h2><table class="threat-table"><thead><tr><th>Severity</th><th>Category</th><th>Type</th><th>Location</th><th>Description</th><th>Matched Pattern</th></tr></thead><tbody>' + threat_rows + '</tbody></table></div>' if threats else '<div class="section"><h2>✅ No Threats Detected</h2><p>Repository appears to be safe and free of detected malicious patterns.</p></div>'}
            </div>
            
            <div class="footer">
                <p>Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                <p>Repository Security Scanner • Protecting Open Source Communities</p>
            </div>
        </div>
    </body>
    </html>
    """
    return html

def get_recommendation(risk_score):
    """Get recommendation based on risk score"""
    if risk_score >= 100:
        return "🔴 CRITICAL: This repository contains serious security threats. DO NOT use or run this code. Contact the repository owner immediately and report the threats."
    elif risk_score >= 50:
        return "🟠 HIGH RISK: This repository contains suspicious patterns that require investigation. Review the code carefully before use. Consider reporting to the maintainer."
    elif risk_score >= 20:
        return "🟡 MEDIUM RISK: This repository has some concerning patterns. Review the flagged code sections and assess the actual intent."
    else:
        return "🟢 SAFE: No significant threats detected. This repository appears safe to use, but always review dependencies and permissions."
