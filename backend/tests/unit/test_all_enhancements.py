"""
Comprehensive test suite for all enhancement modules
"""

import pytest
from datetime import datetime
import json

# Import all services
from services.dashboard_enhancements import DashboardDataGenerator, ReportGenerator, ThemeManager
from services.browser_extension import (TabSandbox, RealTimeURLScanner, AutoProtection,
                                        BrowserNotification, PermissionManager, ContextMenuManager)
from services.intelligence_sources import ThreatIntelligenceAggregator
from services.soc_analyzer_advanced import MITREAttackMapper, LogMonitor, ThreatCorrelation, IncidentResponse
from services.webhook_manager import WebhookManager, EventPublisher, AlertForwarder, SlackIntegration
from services.advanced_reporting import (ThreatReportGenerator, ThreatSignatureGenerator, 
                                         BulkExportManager, AuditReportGenerator)


# ==================== Dashboard Tests ====================

class TestDashboardEnhancements:
    """Test dashboard enhancement features"""
    
    def test_threat_distribution(self):
        """Test threat distribution generation"""
        logs = [
            {'category': 'phishing'},
            {'category': 'malware'},
            {'category': 'phishing'}
        ]
        
        dist = DashboardDataGenerator.generate_threat_distribution(logs)
        assert 'phishing' in dist['labels']
        assert dist['data'][dist['labels'].index('phishing')] == 2
    
    def test_severity_distribution(self):
        """Test severity distribution"""
        logs = [
            {'severity': 'High'},
            {'severity': 'Medium'},
            {'severity': 'High'}
        ]
        
        dist = DashboardDataGenerator.generate_severity_distribution(logs)
        assert dist['High'] == 2
        assert dist['Medium'] == 1
    
    def test_risk_cards(self):
        """Test risk card generation"""
        logs = [
            {'severity': 'High'},
            {'severity': 'Medium'},
            {'severity': 'Low'},
            {'severity': 'Low'}
        ]
        
        cards = DashboardDataGenerator.generate_risk_cards(logs)
        assert len(cards) == 4
        assert cards[0]['title'] == 'Critical Threats'
    
    def test_html_report_generation(self):
        """Test HTML report"""
        logs = [
            {'url': 'https://example.com', 'severity': 'High', 'category': 'phishing', 'timestamp': datetime.now().isoformat()}
        ]
        
        report = ReportGenerator.generate_html_report(logs)
        assert '<!DOCTYPE html>' in report
        assert 'https://example.com' in report
    
    def test_theme_management(self):
        """Test theme management"""
        css = ThemeManager.get_theme_css('dark')
        assert '--primary' in css
        assert '--background' in css


# ==================== Browser Extension Tests ====================

class TestBrowserExtension:
    """Test browser extension features"""
    
    def test_tab_sandbox(self):
        """Test tab sandboxing"""
        sandbox = TabSandbox()
        result = sandbox.sandbox_tab(1, 'https://suspicious.com')
        
        assert result['url'] == 'https://suspicious.com'
        assert 'sandbox_id' in result
    
    def test_url_scanner(self):
        """Test URL scanning"""
        scanner = RealTimeURLScanner()
        scan = scanner.scan_url('https://example.com', tab_id=1)
        
        assert scan['status'] == 'scanning'
        assert scan['url'] == 'https://example.com'
    
    def test_auto_protection(self):
        """Test auto protection"""
        protection = AutoProtection()
        protection.set_protection_level('high')
        
        assert protection.get_protection_level() == 'high'
    
    def test_domain_whitelist(self):
        """Test whitelist management"""
        sandbox = TabSandbox()
        sandbox.whitelist_domain('trusted.com')
        
        assert sandbox.is_whitelisted('trusted.com')
        assert not sandbox.is_whitelisted('untrusted.com')
    
    def test_permission_manager(self):
        """Test permission management"""
        perms = PermissionManager()
        perms.grant_permission('activeTab')
        
        assert perms.has_permission('activeTab')
    
    def test_context_menu(self):
        """Test context menu management"""
        menu = ContextMenuManager()
        item = menu.add_menu_item('Check URL', 'check_url')
        
        assert item['title'] == 'Check URL'
        items = menu.get_menu_items()
        assert len(items) > 0


# ==================== Intelligence Sources Tests ====================

class TestIntelligenceSources:
    """Test threat intelligence integration"""
    
    def test_aggregator_check_url(self):
        """Test URL checking across sources"""
        aggregator = ThreatIntelligenceAggregator()
        result = aggregator.check_url('https://example.com')
        
        assert 'url' in result
        assert 'consensus' in result
        assert 'sources' in result
    
    def test_aggregator_check_ip(self):
        """Test IP checking"""
        aggregator = ThreatIntelligenceAggregator()
        result = aggregator.check_ip('192.168.1.1')
        
        assert 'ip' in result
        assert 'sources' in result


# ==================== SOC Analyzer Tests ====================

class TestSOCAnalyzer:
    """Test SOC analyzer features"""
    
    def test_mitre_mapping(self):
        """Test MITRE ATT&CK mapping"""
        mapper = MITREAttackMapper()
        threat = {
            'type': 'malware',
            'category': 'execution'
        }
        
        tactics = mapper.map_threat_to_tactic(threat)
        assert len(tactics) > 0
    
    def test_tactic_details(self):
        """Test tactic details"""
        mapper = MITREAttackMapper()
        details = mapper.get_tactic_details('execution')
        
        assert details['name'] == 'execution'
        assert 'techniques' in details
    
    def test_log_monitor(self):
        """Test log monitoring"""
        monitor = LogMonitor()
        logs = [
            {'level': 'ERROR', 'message': 'Unauthorized access attempt'},
            {'level': 'WARNING', 'message': 'Suspicious activity detected'}
        ]
        
        count = monitor.ingest_logs(logs)
        assert count == 2
    
    def test_alert_rules(self):
        """Test alert rules"""
        monitor = LogMonitor()
        monitor.add_alert_rule('Unauthorized Access', 'Unauthorized', 'High')
        
        logs = [{'message': 'Unauthorized access attempt', 'level': 'ERROR'}]
        monitor.ingest_logs(logs)
        
        alerts = monitor.get_alerts()
        assert len(alerts) > 0
    
    def test_threat_correlation(self):
        """Test threat correlation"""
        correlation = ThreatCorrelation()
        event1 = {'source_ip': '192.168.1.100', 'target': 'server1'}
        event2 = {'source_ip': '192.168.1.100', 'target': 'server1'}
        
        id1 = correlation.add_event(event1)
        id2 = correlation.add_event(event2)
        
        correlations = correlation.get_correlations_for_event(id1)
        assert len(correlations) > 0
    
    def test_incident_creation(self):
        """Test incident creation"""
        incident_resp = IncidentResponse()
        incident = incident_resp.create_incident(
            'Phishing Campaign',
            'Large-scale phishing',
            'Critical',
            []
        )
        
        assert incident['status'] == 'open'
        assert incident['severity'] == 'Critical'


# ==================== Webhook Tests ====================

class TestWebhooks:
    """Test webhook management"""
    
    def test_webhook_registration(self):
        """Test webhook registration"""
        manager = WebhookManager()
        webhook = manager.register_webhook(
            'Alert',
            'https://example.com/webhook',
            ['threat_detected', 'high_risk']
        )
        
        assert webhook['name'] == 'Alert'
        assert 'threat_detected' in webhook['events']
    
    def test_webhook_triggering(self):
        """Test webhook triggering"""
        manager = WebhookManager()
        manager.register_webhook('Alert', 'https://example.com/webhook', ['threat'])
        
        results = manager.trigger_webhook('threat', {'threat_id': '123'})
        assert len(results) > 0
    
    def test_event_publisher(self):
        """Test event publishing"""
        publisher = EventPublisher()
        event = publisher.publish_threat_event('malware', {'hash': 'abc123'}, 'critical')
        
        assert event['type'] == 'malware'
        assert event['published'] == True
    
    def test_alert_forwarder(self):
        """Test alert forwarding"""
        manager = WebhookManager()
        forwarder = AlertForwarder(manager)
        
        alert = {'id': '123', 'type': 'phishing', 'risk': 95}
        result = forwarder.forward_alert(alert)
        
        assert result['alert_id'] == '123'
    
    def test_slack_integration(self):
        """Test Slack integration"""
        slack = SlackIntegration()
        result = slack.send_threat_alert({'description': 'Test threat'}, 'high')
        
        assert result['status'] == 'sent'


# ==================== Reporting Tests ====================

class TestAdvancedReporting:
    """Test advanced reporting features"""
    
    def test_executive_summary(self):
        """Test executive summary"""
        threats = [
            {'severity': 'Critical'},
            {'severity': 'High'},
            {'severity': 'Medium'},
            {'severity': 'Low'}
        ]
        
        summary = ThreatReportGenerator.generate_executive_summary(threats)
        assert summary['critical_count'] == 1
        assert summary['total_threats'] == 4
    
    def test_csv_report(self):
        """Test CSV report generation"""
        threats = [
            {'id': '1', 'type': 'phishing', 'severity': 'High', 'risk_score': 95}
        ]
        
        csv = ThreatReportGenerator.generate_csv_report(threats)
        assert 'phishing' in csv
        assert 'ID,Type,Severity' in csv
    
    def test_json_report(self):
        """Test JSON report"""
        threats = [
            {'id': '1', 'type': 'malware', 'severity': 'Critical'}
        ]
        
        report = ThreatReportGenerator.generate_json_report(threats)
        assert 'threats' in report
        assert report['threat_count'] == 1
    
    def test_ioc_signature(self):
        """Test IOC signature generation"""
        threat = {
            'type': 'phishing',
            'url': 'https://phishing.com',
            'ip': '1.2.3.4',
            'domain': 'phishing.com'
        }
        
        signature = ThreatSignatureGenerator.generate_ioc_signature(threat)
        assert len(signature['indicators']) >= 3
    
    def test_yara_rule(self):
        """Test YARA rule generation"""
        threat = {'type': 'Trojan', 'url': 'https://malware.com'}
        
        rule = ThreatSignatureGenerator.generate_yara_rule(threat)
        assert 'rule ' in rule
        assert 'TROJAN_threat' in rule
    
    def test_bulk_export(self):
        """Test bulk export"""
        manager = BulkExportManager()
        export = manager.create_export({'threats': []}, 'json', 'export1')
        
        assert export['format'] == 'json'
        assert export['status'] == 'ready'
    
    def test_compliance_report(self):
        """Test compliance report"""
        logs = [{'type': 'log'}, {'type': 'admin'}]
        
        report = AuditReportGenerator.generate_compliance_report(logs, 'iso27001')
        assert report['standard'] == 'iso27001'
        assert 'sections' in report


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
