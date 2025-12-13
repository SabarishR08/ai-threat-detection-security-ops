"""
Webhook Manager - Integration with external systems
"""

import json
import hashlib
from typing import Dict, List, Optional
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


class WebhookManager:
    """Manage webhooks for threat notifications"""
    
    def __init__(self):
        self.webhooks = {}
        self.webhook_logs = []
        self.event_subscriptions = {}
    
    def register_webhook(self, name: str, url: str, events: List[str],
                        secret: str = None, active: bool = True) -> Dict:
        """Register a webhook endpoint"""
        
        webhook_id = hashlib.md5(f"{name}_{url}_{datetime.now().isoformat()}".encode()).hexdigest()
        
        webhook = {
            'id': webhook_id,
            'name': name,
            'url': url,
            'events': events,
            'secret': secret or hashlib.sha256(f"{webhook_id}_{datetime.now().isoformat()}".encode()).hexdigest(),
            'active': active,
            'created_at': datetime.now().isoformat(),
            'last_triggered': None,
            'failure_count': 0,
            'success_count': 0
        }
        
        self.webhooks[webhook_id] = webhook
        
        # Subscribe to events
        for event in events:
            if event not in self.event_subscriptions:
                self.event_subscriptions[event] = []
            self.event_subscriptions[event].append(webhook_id)
        
        return webhook
    
    def trigger_webhook(self, event_type: str, data: Dict) -> List[Dict]:
        """Trigger webhooks for event"""
        
        webhook_ids = self.event_subscriptions.get(event_type, [])
        results = []
        
        for webhook_id in webhook_ids:
            webhook = self.webhooks.get(webhook_id)
            if not webhook or not webhook['active']:
                continue
            
            result = self._send_webhook(webhook, event_type, data)
            results.append(result)
            
            # Update webhook stats
            if result['status'] == 'success':
                webhook['success_count'] += 1
            else:
                webhook['failure_count'] += 1
            
            webhook['last_triggered'] = datetime.now().isoformat()
        
        return results
    
    def _send_webhook(self, webhook: Dict, event_type: str, data: Dict) -> Dict:
        """Send webhook to external URL"""
        
        payload = {
            'webhook_id': webhook['id'],
            'event_type': event_type,
            'data': data,
            'timestamp': datetime.now().isoformat()
        }
        
        # In production, would use requests library to POST
        # For now, simulate the webhook call
        try:
            # Would be: requests.post(webhook['url'], json=payload, headers={...})
            logger.info(f"Webhook triggered: {webhook['name']} -> {event_type}")
            
            log_entry = {
                'webhook_id': webhook['id'],
                'event_type': event_type,
                'status': 'success',
                'timestamp': datetime.now().isoformat(),
                'response_time_ms': 50  # Simulated
            }
        
        except Exception as e:
            logger.error(f"Webhook error: {str(e)}")
            log_entry = {
                'webhook_id': webhook['id'],
                'event_type': event_type,
                'status': 'failed',
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }
        
        self.webhook_logs.append(log_entry)
        return log_entry
    
    def get_webhook(self, webhook_id: str) -> Optional[Dict]:
        """Get webhook details"""
        return self.webhooks.get(webhook_id)
    
    def list_webhooks(self, active_only: bool = True) -> List[Dict]:
        """List all webhooks"""
        
        webhooks = list(self.webhooks.values())
        
        if active_only:
            webhooks = [w for w in webhooks if w['active']]
        
        return webhooks
    
    def delete_webhook(self, webhook_id: str) -> bool:
        """Delete webhook"""
        
        if webhook_id not in self.webhooks:
            return False
        
        webhook = self.webhooks[webhook_id]
        
        # Remove from event subscriptions
        for event in webhook['events']:
            if event in self.event_subscriptions:
                self.event_subscriptions[event] = [
                    wid for wid in self.event_subscriptions[event] if wid != webhook_id
                ]
        
        del self.webhooks[webhook_id]
        return True
    
    def get_webhook_logs(self, webhook_id: str = None, limit: int = 100) -> List[Dict]:
        """Get webhook execution logs"""
        
        logs = self.webhook_logs
        
        if webhook_id:
            logs = [l for l in logs if l['webhook_id'] == webhook_id]
        
        return logs[-limit:]
    
    def update_webhook_status(self, webhook_id: str, active: bool) -> Optional[Dict]:
        """Update webhook active status"""
        
        webhook = self.webhooks.get(webhook_id)
        if webhook:
            webhook['active'] = active
            return webhook
        
        return None


class EventPublisher:
    """Publish threat events for external consumption"""
    
    def __init__(self):
        self.webhook_manager = WebhookManager()
        self.event_queue = []
    
    def publish_threat_event(self, threat_type: str, threat_data: Dict, severity: str = 'medium') -> Dict:
        """Publish threat event"""
        
        event = {
            'id': hashlib.md5(f"{threat_type}_{datetime.now().isoformat()}".encode()).hexdigest(),
            'type': threat_type,
            'severity': severity,
            'data': threat_data,
            'timestamp': datetime.now().isoformat(),
            'published': False
        }
        
        self.event_queue.append(event)
        
        # Trigger webhooks
        results = self.webhook_manager.trigger_webhook(threat_type, threat_data)
        
        event['published'] = True
        event['webhook_results'] = results
        
        return event
    
    def publish_bulk_events(self, events: List[Dict]) -> List[Dict]:
        """Publish multiple events"""
        
        results = []
        for event in events:
            result = self.publish_threat_event(
                threat_type=event.get('type'),
                threat_data=event.get('data'),
                severity=event.get('severity', 'medium')
            )
            results.append(result)
        
        return results
    
    def get_event_queue(self, undelivered_only: bool = False) -> List[Dict]:
        """Get event queue"""
        
        queue = self.event_queue
        
        if undelivered_only:
            queue = [e for e in queue if not e['published']]
        
        return queue
    
    def clear_event_queue(self) -> int:
        """Clear processed events"""
        
        count = len([e for e in self.event_queue if e['published']])
        self.event_queue = [e for e in self.event_queue if not e['published']]
        
        return count


class AlertForwarder:
    """Forward security alerts to external systems"""
    
    def __init__(self, webhook_manager: WebhookManager):
        self.webhook_manager = webhook_manager
        self.forwarded_alerts = []
    
    def forward_alert(self, alert: Dict, destinations: List[str] = None) -> Dict:
        """Forward alert to destinations"""
        
        alert_id = alert.get('id', hashlib.md5(str(alert).encode()).hexdigest())
        
        forwarding_record = {
            'alert_id': alert_id,
            'timestamp': datetime.now().isoformat(),
            'destinations': {},
            'success': True
        }
        
        if destinations:
            for destination in destinations:
                # Forward to specific destination
                forwarding_record['destinations'][destination] = {
                    'status': 'forwarded',
                    'timestamp': datetime.now().isoformat()
                }
        else:
            # Forward using webhooks
            webhook_results = self.webhook_manager.trigger_webhook('alert', alert)
            forwarding_record['webhook_results'] = webhook_results
        
        self.forwarded_alerts.append(forwarding_record)
        
        return forwarding_record
    
    def get_forwarded_alerts(self, limit: int = 50) -> List[Dict]:
        """Get forwarded alerts"""
        
        return self.forwarded_alerts[-limit:]


class SlackIntegration:
    """Slack notification integration"""
    
    def __init__(self, webhook_url: str = None):
        self.webhook_url = webhook_url
    
    def send_threat_alert(self, threat: Dict, severity: str = 'medium') -> Dict:
        """Send threat alert to Slack"""
        
        colors = {
            'critical': '#FF0000',
            'high': '#FF6600',
            'medium': '#FFAA00',
            'low': '#00AA00'
        }
        
        message = {
            'username': 'Threat Detection System',
            'icon_emoji': ':warning:',
            'attachments': [
                {
                    'color': colors.get(severity, '#000000'),
                    'title': f'{severity.upper()} Threat Detected',
                    'text': threat.get('description', ''),
                    'fields': [
                        {
                            'title': 'Type',
                            'value': threat.get('type', 'Unknown'),
                            'short': True
                        },
                        {
                            'title': 'Risk Score',
                            'value': str(threat.get('risk_score', 'N/A')),
                            'short': True
                        },
                        {
                            'title': 'Source',
                            'value': threat.get('source', 'Unknown'),
                            'short': True
                        },
                        {
                            'title': 'Timestamp',
                            'value': threat.get('timestamp', datetime.now().isoformat()),
                            'short': True
                        }
                    ]
                }
            ]
        }
        
        # In production, would POST to webhook_url
        return {
            'status': 'sent',
            'message_id': hashlib.md5(str(message).encode()).hexdigest(),
            'timestamp': datetime.now().isoformat()
        }


class EmailAlertForwarder:
    """Email notification for alerts"""
    
    def __init__(self, smtp_config: Dict = None):
        self.smtp_config = smtp_config or {}
        self.alert_recipients = []
    
    def add_recipient(self, email: str, alert_types: List[str] = None) -> bool:
        """Add email recipient for alerts"""
        
        recipient = {
            'email': email,
            'alert_types': alert_types or ['critical', 'high'],
            'enabled': True,
            'added_at': datetime.now().isoformat()
        }
        
        self.alert_recipients.append(recipient)
        return True
    
    def send_threat_email(self, threat: Dict, recipient: str = None) -> Dict:
        """Send threat alert via email"""
        
        subject = f"[ALERT] {threat.get('severity', 'MEDIUM').upper()} Threat Detected"
        
        body = f"""
        Threat Alert
        =============
        
        Type: {threat.get('type', 'Unknown')}
        Severity: {threat.get('severity', 'Unknown')}
        Risk Score: {threat.get('risk_score', 'N/A')}/100
        
        Description:
        {threat.get('description', 'No description')}
        
        Time: {threat.get('timestamp', datetime.now().isoformat())}
        
        Please investigate immediately.
        """
        
        return {
            'status': 'sent',
            'to': recipient or ', '.join([r['email'] for r in self.alert_recipients]),
            'subject': subject,
            'message_id': hashlib.md5(str(body).encode()).hexdigest(),
            'timestamp': datetime.now().isoformat()
        }
    
    def get_recipients(self) -> List[Dict]:
        """Get all alert recipients"""
        
        return self.alert_recipients


class SIEMIntegration:
    """Integration with SIEM systems (Splunk, ELK, etc.)"""
    
    def __init__(self, siem_endpoint: str = None):
        self.siem_endpoint = siem_endpoint
        self.events_sent = []
    
    def send_event(self, event: Dict) -> Dict:
        """Send event to SIEM"""
        
        siem_formatted = {
            'event_type': event.get('type'),
            'severity': event.get('severity'),
            'timestamp': event.get('timestamp', datetime.now().isoformat()),
            'source': 'ThreatDetectionSystem',
            'details': event.get('details', {}),
            'host': event.get('host', 'unknown'),
            'user': event.get('user', 'unknown')
        }
        
        # In production, would send to SIEM endpoint
        result = {
            'status': 'sent',
            'event_id': hashlib.md5(str(siem_formatted).encode()).hexdigest(),
            'timestamp': datetime.now().isoformat()
        }
        
        self.events_sent.append(result)
        return result
    
    def bulk_send(self, events: List[Dict]) -> List[Dict]:
        """Send multiple events to SIEM"""
        
        results = []
        for event in events:
            result = self.send_event(event)
            results.append(result)
        
        return results
    
    def get_sent_events(self, limit: int = 100) -> List[Dict]:
        """Get events sent to SIEM"""
        
        return self.events_sent[-limit:]
