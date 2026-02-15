"""
SOC Analyzer Enhancement - MITRE ATT&CK mapping, log monitoring, threat correlation
"""

import json
from typing import Dict, List, Optional
from datetime import datetime, timedelta
import hashlib


class MITREAttackMapper:
    """Map threats to MITRE ATT&CK framework"""
    
    TACTICS = {
        'reconnaissance': {
            'id': 'TA0043',
            'techniques': ['T1589', 'T1590', 'T1598', 'T1597', 'T1591']
        },
        'resource_development': {
            'id': 'TA0042',
            'techniques': ['T1583', 'T1586', 'T1584', 'T1587', 'T1585']
        },
        'initial_access': {
            'id': 'TA0001',
            'techniques': ['T1189', 'T1195', 'T1199', 'T1200', 'T1566']
        },
        'execution': {
            'id': 'TA0002',
            'techniques': ['T1059', 'T1059.001', 'T1059.003', 'T1203', 'T1559']
        },
        'persistence': {
            'id': 'TA0003',
            'techniques': ['T1098', 'T1197', 'T1547', 'T1547.001', 'T1547.014']
        },
        'privilege_escalation': {
            'id': 'TA0004',
            'techniques': ['T1134', 'T1134.003', 'T1134.004', 'T1134.005', 'T1548']
        },
        'defense_evasion': {
            'id': 'TA0005',
            'techniques': ['T1548', 'T1197', 'T1140', 'T1202', 'T1036']
        },
        'credential_access': {
            'id': 'TA0006',
            'techniques': ['T1110', 'T1555', 'T1187', 'T1040', 'T1056']
        },
        'discovery': {
            'id': 'TA0007',
            'techniques': ['T1087', 'T1010', 'T1217', 'T1538', 'T1526']
        },
        'lateral_movement': {
            'id': 'TA0008',
            'techniques': ['T1210', 'T1570', 'T1021', 'T1570', 'T1570']
        },
        'collection': {
            'id': 'TA0009',
            'techniques': ['T1123', 'T1119', 'T1115', 'T1530', 'T1557']
        },
        'command_and_control': {
            'id': 'TA0011',
            'techniques': ['T1071', 'T1092', 'T1001', 'T1008', 'T1105']
        },
        'exfiltration': {
            'id': 'TA0010',
            'techniques': ['T1020', 'T1030', 'T1048', 'T1041', 'T1011']
        },
        'impact': {
            'id': 'TA0040',
            'techniques': ['T1531', 'T1561', 'T1499', 'T1561', 'T1485']
        }
    }
    
    def map_threat_to_tactic(self, threat: Dict) -> List[str]:
        """Map threat to MITRE ATT&CK tactics"""
        
        tactics = []
        threat_type = threat.get('type', '').lower()
        threat_payload = threat.get('payload', '').lower()
        threat_category = threat.get('category', '').lower()
        
        # Map based on threat characteristics
        if 'malware' in threat_type or 'executable' in threat_payload:
            tactics.extend(['execution', 'persistence', 'privilege_escalation'])
        
        if 'phishing' in threat_type or 'email' in threat_payload:
            tactics.extend(['initial_access', 'credential_access'])
        
        if 'scan' in threat_type or 'reconnaissance' in threat_category:
            tactics.append('reconnaissance')
        
        if 'exfiltration' in threat_category or 'data-stealing' in threat_type:
            tactics.append('exfiltration')
        
        if 'c2' in threat_type or 'command' in threat_category:
            tactics.append('command_and_control')
        
        return list(set(tactics))
    
    def get_tactic_details(self, tactic_name: str) -> Dict:
        """Get MITRE ATT&CK tactic details"""
        
        tactic = self.TACTICS.get(tactic_name.lower())
        if tactic:
            return {
                'name': tactic_name,
                'id': tactic['id'],
                'techniques': tactic['techniques'],
                'description': self._get_tactic_description(tactic_name)
            }
        return {}
    
    def _get_tactic_description(self, tactic_name: str) -> str:
        """Get tactic description"""
        
        descriptions = {
            'reconnaissance': 'Gather information used to plan future operations',
            'resource_development': 'Obtain, improve, and position resources for initial access',
            'initial_access': 'Get into the network',
            'execution': 'Run malware or code',
            'persistence': 'Maintain access to systems',
            'privilege_escalation': 'Gain higher level permissions',
            'defense_evasion': 'Avoid detection and removal',
            'credential_access': 'Obtain valid account credentials',
            'discovery': 'Discover and gather information about systems',
            'lateral_movement': 'Move across internal network',
            'collection': 'Gather data and files for exfiltration',
            'command_and_control': 'Communicate with and control compromised systems',
            'exfiltration': 'Steal data',
            'impact': 'Damage or disrupt systems and data'
        }
        
        return descriptions.get(tactic_name.lower(), 'Unknown tactic')


class LogMonitor:
    """Monitor and analyze logs for threats"""
    
    def __init__(self):
        self.logs = []
        self.alert_rules = []
        self.alerts = []
        self.log_sources = {}
    
    def add_log_source(self, name: str, log_type: str, config: Dict) -> Dict:
        """Add log source to monitor"""
        
        source = {
            'name': name,
            'type': log_type,
            'config': config,
            'enabled': True,
            'last_sync': None,
            'status': 'not_connected'
        }
        
        self.log_sources[name] = source
        return source
    
    def ingest_logs(self, logs: List[Dict], source_name: str = 'default') -> int:
        """Ingest logs for analysis"""
        
        ingested_count = 0
        for log in logs:
            processed_log = {
                'id': hashlib.md5(f"{source_name}_{datetime.now().isoformat()}".encode()).hexdigest(),
                'source': source_name,
                'timestamp': log.get('timestamp', datetime.now().isoformat()),
                'level': log.get('level', 'INFO'),
                'message': log.get('message', ''),
                'data': log
            }
            
            self.logs.append(processed_log)
            ingested_count += 1
            
            # Check against alert rules
            self._check_alert_rules(processed_log)
        
        return ingested_count
    
    def add_alert_rule(self, name: str, pattern: str, severity: str,
                      action: str = 'alert') -> Dict:
        """Add log alert rule"""
        
        rule = {
            'id': hashlib.md5(f"{name}_{datetime.now().isoformat()}".encode()).hexdigest(),
            'name': name,
            'pattern': pattern,
            'severity': severity,
            'action': action,
            'enabled': True,
            'triggered_count': 0
        }
        
        self.alert_rules.append(rule)
        return rule
    
    def _check_alert_rules(self, log: Dict) -> None:
        """Check log against all alert rules"""
        
        for rule in self.alert_rules:
            if not rule['enabled']:
                continue
            
            if rule['pattern'].lower() in log['message'].lower():
                alert = {
                    'id': hashlib.md5(f"{log['id']}_{rule['id']}".encode()).hexdigest(),
                    'rule_id': rule['id'],
                    'rule_name': rule['name'],
                    'log_id': log['id'],
                    'severity': rule['severity'],
                    'timestamp': datetime.now().isoformat(),
                    'message': log['message'],
                    'source': log['source']
                }
                
                self.alerts.append(alert)
                rule['triggered_count'] += 1
    
    def get_logs(self, source: str = None, level: str = None,
                start_time: str = None, limit: int = 100) -> List[Dict]:
        """Query logs with filters"""
        
        filtered_logs = self.logs
        
        if source:
            filtered_logs = [l for l in filtered_logs if l['source'] == source]
        
        if level:
            filtered_logs = [l for l in filtered_logs if l['level'] == level]
        
        if start_time:
            filtered_logs = [l for l in filtered_logs if l['timestamp'] >= start_time]
        
        return filtered_logs[-limit:]
    
    def get_alerts(self, severity: str = None, limit: int = 50) -> List[Dict]:
        """Get triggered alerts"""
        
        filtered_alerts = self.alerts
        
        if severity:
            filtered_alerts = [a for a in filtered_alerts if a['severity'] == severity]
        
        return filtered_alerts[-limit:]


class ThreatCorrelation:
    """Correlate threats across multiple sources"""
    
    def __init__(self):
        self.events = []
        self.correlations = []
        self.threat_chains = []
    
    def add_event(self, event: Dict) -> str:
        """Add security event"""
        
        event_id = hashlib.md5(f"{event}_{datetime.now().isoformat()}".encode()).hexdigest()
        
        event_with_id = {
            'id': event_id,
            'timestamp': event.get('timestamp', datetime.now().isoformat()),
            **event
        }
        
        self.events.append(event_with_id)
        
        # Check for correlations
        self._check_correlations(event_with_id)
        
        return event_id
    
    def _check_correlations(self, event: Dict) -> None:
        """Check event for correlations with existing events"""
        
        for other_event in self.events[:-1]:  # Exclude the event just added
            if self._events_correlated(event, other_event):
                correlation = {
                    'id': hashlib.md5(f"{event['id']}_{other_event['id']}".encode()).hexdigest(),
                    'event1_id': event['id'],
                    'event2_id': other_event['id'],
                    'correlation_type': self._get_correlation_type(event, other_event),
                    'confidence': self._calculate_correlation_confidence(event, other_event),
                    'discovered_at': datetime.now().isoformat()
                }
                
                self.correlations.append(correlation)
                
                # Build threat chain
                self._add_to_threat_chain(event, other_event)
    
    def _events_correlated(self, event1: Dict, event2: Dict) -> bool:
        """Check if two events are correlated"""
        
        # Same source IP
        if event1.get('source_ip') == event2.get('source_ip'):
            return True
        
        # Same target
        if event1.get('target') == event2.get('target'):
            return True
        
        # Similar indicators
        if event1.get('ioc') == event2.get('ioc'):
            return True
        
        # Temporal correlation (within 5 minutes)
        time1 = datetime.fromisoformat(event1.get('timestamp', datetime.now().isoformat()))
        time2 = datetime.fromisoformat(event2.get('timestamp', datetime.now().isoformat()))
        
        if abs((time1 - time2).total_seconds()) < 300:
            return True
        
        return False
    
    def _get_correlation_type(self, event1: Dict, event2: Dict) -> str:
        """Determine correlation type"""
        
        if event1.get('source_ip') == event2.get('source_ip'):
            return 'same_source'
        elif event1.get('target') == event2.get('target'):
            return 'same_target'
        elif event1.get('ioc') == event2.get('ioc'):
            return 'same_ioc'
        else:
            return 'temporal'
    
    def _calculate_correlation_confidence(self, event1: Dict, event2: Dict) -> float:
        """Calculate correlation confidence score"""
        
        confidence = 0.0
        
        # Exact matches boost confidence
        if event1.get('source_ip') == event2.get('source_ip'):
            confidence += 0.3
        
        if event1.get('target') == event2.get('target'):
            confidence += 0.3
        
        if event1.get('ioc') == event2.get('ioc'):
            confidence += 0.3
        
        # Temporal proximity
        time1 = datetime.fromisoformat(event1.get('timestamp', datetime.now().isoformat()))
        time2 = datetime.fromisoformat(event2.get('timestamp', datetime.now().isoformat()))
        
        time_diff = abs((time1 - time2).total_seconds())
        if time_diff < 60:
            confidence += 0.1
        elif time_diff < 300:
            confidence += 0.05
        
        return min(confidence, 1.0)
    
    def _add_to_threat_chain(self, event: Dict, other_event: Dict) -> None:
        """Add correlated events to threat chain"""
        
        # Check if events are already in a chain
        chain_found = False
        for chain in self.threat_chains:
            if event['id'] in chain['event_ids'] or other_event['id'] in chain['event_ids']:
                if event['id'] not in chain['event_ids']:
                    chain['event_ids'].append(event['id'])
                if other_event['id'] not in chain['event_ids']:
                    chain['event_ids'].append(other_event['id'])
                chain_found = True
                break
        
        # Create new chain if needed
        if not chain_found:
            chain = {
                'id': hashlib.md5(f"{event['id']}_{other_event['id']}_{datetime.now().isoformat()}".encode()).hexdigest(),
                'event_ids': [event['id'], other_event['id']],
                'severity': max(event.get('severity', 'Low'), other_event.get('severity', 'Low')),
                'created_at': datetime.now().isoformat()
            }
            self.threat_chains.append(chain)
    
    def get_threat_chains(self, severity: str = None) -> List[Dict]:
        """Get threat chains"""
        
        chains = self.threat_chains
        
        if severity:
            chains = [c for c in chains if c['severity'] == severity]
        
        return chains
    
    def get_correlations_for_event(self, event_id: str) -> List[Dict]:
        """Get all correlations for an event"""
        
        correlations = [
            c for c in self.correlations
            if c['event1_id'] == event_id or c['event2_id'] == event_id
        ]
        
        return correlations


class IncidentResponse:
    """Incident response automation"""
    
    def __init__(self):
        self.incidents = []
        self.playbooks = {}
        self.response_actions = []
    
    def create_incident(self, title: str, description: str, severity: str,
                       events: List[str]) -> Dict:
        """Create security incident"""
        
        incident = {
            'id': hashlib.md5(f"{title}_{datetime.now().isoformat()}".encode()).hexdigest(),
            'title': title,
            'description': description,
            'severity': severity,
            'status': 'open',
            'events': events,
            'created_at': datetime.now().isoformat(),
            'updated_at': datetime.now().isoformat(),
            'assigned_to': None,
            'resolution_notes': None
        }
        
        self.incidents.append(incident)
        return incident
    
    def add_playbook(self, name: str, trigger_condition: str, steps: List[Dict]) -> Dict:
        """Add incident response playbook"""
        
        playbook = {
            'id': hashlib.md5(f"{name}_{datetime.now().isoformat()}".encode()).hexdigest(),
            'name': name,
            'trigger_condition': trigger_condition,
            'steps': steps,
            'enabled': True,
            'executions': 0
        }
        
        self.playbooks[name] = playbook
        return playbook
    
    def execute_playbook(self, playbook_name: str, incident_id: str) -> Dict:
        """Execute incident response playbook"""
        
        playbook = self.playbooks.get(playbook_name)
        if not playbook:
            return {'error': 'Playbook not found'}
        
        execution = {
            'id': hashlib.md5(f"{incident_id}_{playbook_name}_{datetime.now().isoformat()}".encode()).hexdigest(),
            'playbook_id': playbook['id'],
            'incident_id': incident_id,
            'steps_executed': [],
            'status': 'executing',
            'started_at': datetime.now().isoformat()
        }
        
        for step in playbook['steps']:
            execution['steps_executed'].append({
                'step_name': step.get('name'),
                'status': 'pending',
                'executed_at': None
            })
        
        self.response_actions.append(execution)
        playbook['executions'] += 1
        
        return execution
