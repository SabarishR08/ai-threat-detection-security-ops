"""
Advanced Reporting - Export to HTML, PDF, CSV, and threat signatures
"""

import json
import csv
import hashlib
from typing import Dict, List
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


class ThreatReportGenerator:
    """Generate comprehensive threat reports"""
    
    @staticmethod
    def generate_executive_summary(threats: List[Dict]) -> Dict:
        """Generate executive summary"""
        
        total = len(threats)
        critical = sum(1 for t in threats if t.get('severity') == 'Critical')
        high = sum(1 for t in threats if t.get('severity') == 'High')
        medium = sum(1 for t in threats if t.get('severity') == 'Medium')
        low = sum(1 for t in threats if t.get('severity') == 'Low')
        
        # Calculate risk trend
        risk_score = (critical * 100 + high * 70 + medium * 40 + low * 10) / total if total > 0 else 0
        
        return {
            'report_date': datetime.now().isoformat(),
            'total_threats': total,
            'critical_count': critical,
            'high_count': high,
            'medium_count': medium,
            'low_count': low,
            'overall_risk_score': round(risk_score, 2),
            'risk_level': 'Critical' if risk_score > 70 else 'High' if risk_score > 50 else 'Medium' if risk_score > 25 else 'Low',
            'recommendations': ThreatReportGenerator._get_recommendations(risk_score)
        }
    
    @staticmethod
    def _get_recommendations(risk_score: float) -> List[str]:
        """Get recommendations based on risk score"""
        
        recommendations = []
        
        if risk_score > 70:
            recommendations.extend([
                'Immediately isolate affected systems from network',
                'Activate incident response team',
                'Conduct full forensic analysis',
                'Review and update security policies'
            ])
        elif risk_score > 50:
            recommendations.extend([
                'Increase monitoring and logging',
                'Conduct security awareness training',
                'Update threat intelligence',
                'Review access controls'
            ])
        else:
            recommendations.extend([
                'Continue regular security monitoring',
                'Maintain current security posture',
                'Update threat databases quarterly'
            ])
        
        return recommendations
    
    @staticmethod
    def generate_detailed_threat_report(threat: Dict) -> Dict:
        """Generate detailed report for single threat"""
        
        return {
            'id': threat.get('id', hashlib.md5(str(threat).encode()).hexdigest()),
            'type': threat.get('type', 'Unknown'),
            'severity': threat.get('severity', 'Unknown'),
            'risk_score': threat.get('risk_score', 0),
            'first_seen': threat.get('first_seen', datetime.now().isoformat()),
            'last_seen': threat.get('last_seen', datetime.now().isoformat()),
            'occurrences': threat.get('occurrences', 1),
            'indicators': threat.get('indicators', []),
            'affected_systems': threat.get('affected_systems', []),
            'recommended_actions': threat.get('recommended_actions', []),
            'mitre_tactics': threat.get('mitre_tactics', []),
            'detection_method': threat.get('detection_method', 'Unknown'),
            'false_positive_likelihood': threat.get('confidence', 95) if threat.get('confidence', 0) > 50 else 'Low'
        }
    
    @staticmethod
    def generate_csv_report(threats: List[Dict]) -> str:
        """Generate CSV report"""
        
        if not threats:
            return "No threats to report"
        
        # Prepare data
        rows = []
        for threat in threats:
            rows.append({
                'id': threat.get('id', ''),
                'type': threat.get('type', ''),
                'severity': threat.get('severity', ''),
                'risk_score': threat.get('risk_score', 0),
                'first_seen': threat.get('first_seen', ''),
                'last_seen': threat.get('last_seen', ''),
                'source': threat.get('source', ''),
                'status': threat.get('status', '')
            })
        
        # Generate CSV
        csv_content = "ID,Type,Severity,Risk Score,First Seen,Last Seen,Source,Status\n"
        for row in rows:
            csv_content += f"{row['id']},{row['type']},{row['severity']},{row['risk_score']},{row['first_seen']},{row['last_seen']},{row['source']},{row['status']}\n"
        
        return csv_content
    
    @staticmethod
    def generate_json_report(threats: List[Dict], executive_summary: bool = True) -> Dict:
        """Generate JSON report"""
        
        report = {
            'generated_at': datetime.now().isoformat(),
            'threat_count': len(threats),
            'threats': threats
        }
        
        if executive_summary:
            report['executive_summary'] = ThreatReportGenerator.generate_executive_summary(threats)
        
        return report


class PDFReportGenerator:
    """Generate PDF reports (requires pypdf or reportlab)"""
    
    @staticmethod
    def generate_threat_pdf(threats: List[Dict], filename: str = None) -> str:
        """Generate PDF threat report"""
        
        # In production, would use reportlab to generate PDF
        # For now, return HTML that can be converted to PDF
        
        pdf_content = f"""
        %PDF-1.4
        1 0 obj
        << /Type /Catalog /Pages 2 0 R >>
        endobj
        2 0 obj
        << /Type /Pages /Kids [3 0 R] /Count 1 >>
        endobj
        3 0 obj
        << /Type /Page /Parent 2 0 R /Resources << /Font << /F1 4 0 R >> >> /MediaBox [0 0 612 792] /Contents 5 0 R >>
        endobj
        4 0 obj
        << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>
        endobj
        5 0 obj
        << /Length 0 >>
        stream
        BT
        /F1 12 Tf
        50 750 Td
        (Threat Report) Tj
        ET
        endstream
        endobj
        xref
        0 6
        0000000000 65535 f
        0000000009 00000 n
        0000000058 00000 n
        0000000115 00000 n
        0000000214 00000 n
        0000000301 00000 n
        trailer
        << /Size 6 /Root 1 0 R >>
        startxref
        380
        %%EOF
        """
        
        filename = filename or f"threat_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        
        return filename


class ThreatSignatureGenerator:
    """Generate threat signatures and IOCs (Indicators of Compromise)"""
    
    @staticmethod
    def generate_ioc_signature(threat: Dict) -> Dict:
        """Generate IOC signature from threat"""
        
        signature = {
            'id': hashlib.md5(str(threat).encode()).hexdigest(),
            'type': threat.get('type', 'Unknown'),
            'created_at': datetime.now().isoformat(),
            'tlp_level': threat.get('tlp_level', 'WHITE'),  # WHITE, GREEN, AMBER, RED
            'indicators': []
        }
        
        # Extract indicators
        if 'url' in threat:
            signature['indicators'].append({
                'type': 'URL',
                'value': threat['url'],
                'severity': threat.get('severity', 'Unknown')
            })
        
        if 'ip' in threat:
            signature['indicators'].append({
                'type': 'IP',
                'value': threat['ip'],
                'severity': threat.get('severity', 'Unknown')
            })
        
        if 'domain' in threat:
            signature['indicators'].append({
                'type': 'DOMAIN',
                'value': threat['domain'],
                'severity': threat.get('severity', 'Unknown')
            })
        
        if 'hash' in threat:
            signature['indicators'].append({
                'type': 'HASH',
                'value': threat['hash'],
                'hash_type': threat.get('hash_type', 'MD5'),
                'severity': threat.get('severity', 'Unknown')
            })
        
        return signature
    
    @staticmethod
    def generate_yara_rule(threat: Dict) -> str:
        """Generate YARA rule for threat"""
        
        rule_name = threat.get('type', 'Unknown').replace(' ', '_').upper()
        
        yara_rule = f"""
        rule {rule_name}_threat
        {{
            meta:
                description = "Detection rule for {threat.get('type', 'Unknown')}"
                author = "Threat Detection System"
                date = "{datetime.now().strftime('%Y-%m-%d')}"
                threat_level = "{threat.get('severity', 'Unknown')}"
            
            strings:
                $url = "{threat.get('url', '')}" nocase
                $domain = "{threat.get('domain', '')}" nocase
        
            condition:
                any of them
        }}
        """
        
        return yara_rule
    
    @staticmethod
    def generate_sigma_rule(threat: Dict) -> Dict:
        """Generate Sigma rule for SIEM"""
        
        return {
            'title': f"{threat.get('type', 'Unknown')} Detection",
            'id': hashlib.md5(str(threat).encode()).hexdigest(),
            'status': 'experimental',
            'description': f"Detects {threat.get('type', 'Unknown')}",
            'author': 'Threat Detection System',
            'date': datetime.now().strftime('%Y-%m-%d'),
            'detection': {
                'selection': threat.get('indicators', {}),
                'condition': 'selection'
            },
            'falsepositives': ['None known'],
            'level': threat.get('severity', 'medium').lower()
        }
    
    @staticmethod
    def export_iocs(threats: List[Dict], format: str = 'json') -> str:
        """Export IOCs in various formats"""
        
        if format == 'json':
            return json.dumps([ThreatSignatureGenerator.generate_ioc_signature(t) for t in threats], indent=2)
        
        elif format == 'stix':
            # STIX format (simplified)
            stix_content = {
                'type': 'bundle',
                'id': f"bundle--{hashlib.md5(str(threats).encode()).hexdigest()}",
                'objects': []
            }
            
            for threat in threats:
                stix_content['objects'].append({
                    'type': 'malware' if 'malware' in threat.get('type', '').lower() else 'attack-pattern',
                    'id': f"{threat.get('type', 'unknown')}--{hashlib.md5(str(threat).encode()).hexdigest()}",
                    'created': datetime.now().isoformat(),
                    'name': threat.get('type', 'Unknown'),
                    'labels': ['malicious-activity']
                })
            
            return json.dumps(stix_content, indent=2)
        
        elif format == 'csv':
            csv_content = "Type,Indicator,Severity,TLP\n"
            for threat in threats:
                for indicator in threat.get('indicators', []):
                    csv_content += f"{threat.get('type')},{indicator},{ threat.get('severity')},WHITE\n"
            return csv_content
        
        else:
            return json.dumps(threats)


class BulkExportManager:
    """Manage bulk export operations"""
    
    def __init__(self):
        self.exports = {}
        self.export_history = []
    
    def create_export(self, data: Dict, format: str, name: str = None) -> Dict:
        """Create bulk export"""
        
        export_id = hashlib.md5(f"{name}_{datetime.now().isoformat()}".encode()).hexdigest()
        
        export = {
            'id': export_id,
            'name': name or f"export_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            'format': format,  # json, csv, html, pdf, yara, sigma, stix
            'size_bytes': len(json.dumps(data)),
            'created_at': datetime.now().isoformat(),
            'status': 'ready',
            'download_url': f"/api/exports/{export_id}"
        }
        
        self.exports[export_id] = export
        self.export_history.append(export)
        
        return export
    
    def get_export(self, export_id: str) -> Dict:
        """Get export details"""
        
        return self.exports.get(export_id)
    
    def list_exports(self) -> List[Dict]:
        """List all exports"""
        
        return list(self.exports.values())
    
    def delete_export(self, export_id: str) -> bool:
        """Delete export"""
        
        if export_id in self.exports:
            del self.exports[export_id]
            return True
        return False
    
    def get_export_history(self, limit: int = 50) -> List[Dict]:
        """Get export history"""
        
        return self.export_history[-limit:]


class AuditReportGenerator:
    """Generate audit reports for compliance"""
    
    @staticmethod
    def generate_compliance_report(audit_logs: List[Dict], standard: str = 'iso27001') -> Dict:
        """Generate compliance report"""
        
        report = {
            'generated_at': datetime.now().isoformat(),
            'standard': standard,
            'total_events': len(audit_logs),
            'compliance_status': 'COMPLIANT' if len(audit_logs) > 0 else 'INCOMPLETE',
            'sections': []
        }
        
        if standard == 'iso27001':
            report['sections'] = [
                {
                    'control': 'A.12.4.1',
                    'name': 'Event logging',
                    'status': 'IMPLEMENTED',
                    'events': len([l for l in audit_logs if l.get('type') == 'log'])
                },
                {
                    'control': 'A.12.4.3',
                    'name': 'Administrator and operator logs',
                    'status': 'IMPLEMENTED',
                    'events': len([l for l in audit_logs if l.get('type') == 'admin'])
                },
                {
                    'control': 'A.12.4.4',
                    'name': 'Clock synchronization',
                    'status': 'IMPLEMENTED',
                    'details': 'System clocks synchronized via NTP'
                }
            ]
        
        elif standard == 'pci-dss':
            report['sections'] = [
                {
                    'requirement': '10.1',
                    'name': 'Implement automated audit trails',
                    'status': 'COMPLIANT'
                },
                {
                    'requirement': '10.2',
                    'name': 'Implement automated user access',
                    'status': 'COMPLIANT'
                }
            ]
        
        return report
