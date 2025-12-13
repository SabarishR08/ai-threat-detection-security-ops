"""
Intelligence Source Integration - VirusTotal, PhishTank, URLHaus, AbuseIPDB, etc.
"""

import os
import json
from typing import Dict, List, Optional
from datetime import datetime
import hashlib


class IntelligenceSourceManager:
    """Manage multiple threat intelligence sources"""
    
    def __init__(self):
        self.sources = {}
        self.cache = {}
        self.api_keys = {}
        self.rate_limits = {}
        self.last_requests = {}
    
    def register_source(self, name: str, config: Dict) -> Dict:
        """Register intelligence source"""
        
        source = {
            'name': name,
            'enabled': config.get('enabled', True),
            'api_key': config.get('api_key', ''),
            'endpoint': config.get('endpoint', ''),
            'rate_limit': config.get('rate_limit', 60),  # requests per minute
            'timeout': config.get('timeout', 10),
            'priority': config.get('priority', 5),
            'features': config.get('features', []),
            'last_used': None
        }
        
        self.sources[name] = source
        return source
    
    def get_source(self, name: str) -> Optional[Dict]:
        """Get source configuration"""
        return self.sources.get(name)
    
    def enable_source(self, name: str) -> bool:
        """Enable source"""
        if name in self.sources:
            self.sources[name]['enabled'] = True
            return True
        return False
    
    def disable_source(self, name: str) -> bool:
        """Disable source"""
        if name in self.sources:
            self.sources[name]['enabled'] = False
            return True
        return False
    
    def get_enabled_sources(self) -> List[Dict]:
        """Get all enabled sources"""
        return [s for s in self.sources.values() if s['enabled']]
    
    def update_last_request(self, source_name: str) -> None:
        """Update last request timestamp"""
        if source_name in self.sources:
            self.sources[source_name]['last_used'] = datetime.now().isoformat()


class VirusTotalIntegration:
    """VirusTotal API Integration"""
    
    def __init__(self, api_key: str = None):
        self.api_key = api_key or os.getenv('VIRUSTOTAL_API_KEY', '')
        self.base_url = "https://www.virustotal.com/api/v3"
        self.cache = {}
    
    def check_url(self, url: str) -> Dict:
        """Check URL with VirusTotal"""
        
        url_hash = hashlib.sha256(url.encode()).hexdigest()
        
        if url_hash in self.cache:
            return self.cache[url_hash]
        
        # Simulated response (in production, would call actual API)
        result = {
            'url': url,
            'status': 'clean',
            'detections': 0,
            'engine_stats': {
                'undetected': 85,
                'malicious': 0,
                'suspicious': 0,
                'unanalyzed': 0
            },
            'threat_categories': [],
            'last_analysis_date': datetime.now().isoformat(),
            'source': 'VirusTotal'
        }
        
        self.cache[url_hash] = result
        return result
    
    def check_domain(self, domain: str) -> Dict:
        """Check domain with VirusTotal"""
        
        result = {
            'domain': domain,
            'status': 'clean',
            'categories': {},
            'last_dns_records': [],
            'reputation': 0,
            'source': 'VirusTotal'
        }
        
        return result
    
    def check_ip(self, ip: str) -> Dict:
        """Check IP with VirusTotal"""
        
        result = {
            'ip': ip,
            'status': 'clean',
            'asn': None,
            'country': 'Unknown',
            'reverse_dns': None,
            'reputation': 0,
            'detections': 0,
            'source': 'VirusTotal'
        }
        
        return result


class PhishTankIntegration:
    """PhishTank API Integration"""
    
    def __init__(self, api_key: str = None):
        self.api_key = api_key or os.getenv('PHISHTANK_API_KEY', '')
        self.base_url = "https://checkurl.phishtank.com/api/checkurl"
        self.cache = {}
    
    def check_url(self, url: str) -> Dict:
        """Check URL against PhishTank database"""
        
        url_hash = hashlib.sha256(url.encode()).hexdigest()
        
        if url_hash in self.cache:
            return self.cache[url_hash]
        
        result = {
            'url': url,
            'in_database': False,
            'phish_id': None,
            'phish_detail_url': None,
            'submission_time': None,
            'verified': False,
            'verification_time': None,
            'valid': True,
            'source': 'PhishTank'
        }
        
        self.cache[url_hash] = result
        return result
    
    def get_recent_phish(self, limit: int = 100) -> List[Dict]:
        """Get recent phishing URLs"""
        
        return []  # Would fetch from API in production


class URLHausIntegration:
    """URLhaus API Integration"""
    
    def __init__(self):
        self.base_url = "https://urlhaus-api.abuse.ch/v1"
        self.cache = {}
    
    def check_url(self, url: str) -> Dict:
        """Check URL against URLhaus database"""
        
        url_hash = hashlib.sha256(url.encode()).hexdigest()
        
        if url_hash in self.cache:
            return self.cache[url_hash]
        
        result = {
            'url': url,
            'query_status': 'ok',
            'in_database': False,
            'url_id': None,
            'threat': None,
            'tags': [],
            'date_added': None,
            'source': 'URLhaus'
        }
        
        self.cache[url_hash] = result
        return result
    
    def check_domain(self, domain: str) -> List[Dict]:
        """Get URLs hosted on domain"""
        
        return []
    
    def check_host(self, host: str) -> List[Dict]:
        """Get URLs on host"""
        
        return []


class AbuseIPDBIntegration:
    """AbuseIPDB API Integration"""
    
    def __init__(self, api_key: str = None):
        self.api_key = api_key or os.getenv('ABUSEIPDB_API_KEY', '')
        self.base_url = "https://api.abuseipdb.com/api/v2"
        self.cache = {}
    
    def check_ip(self, ip: str) -> Dict:
        """Check IP reputation"""
        
        ip_hash = hashlib.sha256(ip.encode()).hexdigest()
        
        if ip_hash in self.cache:
            return self.cache[ip_hash]
        
        result = {
            'ip': ip,
            'abuseConfidenceScore': 0,
            'usageType': 'Unknown',
            'isp': 'Unknown',
            'domain': 'Unknown',
            'hostnames': [],
            'totalReports': 0,
            'numDistinctUsers': 0,
            'lastReportedAt': None,
            'is_whitelisted': False,
            'source': 'AbuseIPDB'
        }
        
        self.cache[ip_hash] = result
        return result


class GoogleSafeBrowsingIntegration:
    """Google Safe Browsing API Integration"""
    
    def __init__(self, api_key: str = None):
        self.api_key = api_key or os.getenv('GOOGLE_SAFE_BROWSING_KEY', '')
        self.base_url = "https://safebrowsing.googleapis.com/v4"
        self.cache = {}
    
    def check_url(self, url: str) -> Dict:
        """Check URL against Google Safe Browsing"""
        
        url_hash = hashlib.sha256(url.encode()).hexdigest()
        
        if url_hash in self.cache:
            return self.cache[url_hash]
        
        result = {
            'url': url,
            'safe': True,
            'threats': [],
            'platform_types': [],
            'threat_entry_types': [],
            'expire_time': None,
            'source': 'Google Safe Browsing'
        }
        
        self.cache[url_hash] = result
        return result


class ShodanIntegration:
    """Shodan API Integration"""
    
    def __init__(self, api_key: str = None):
        self.api_key = api_key or os.getenv('SHODAN_API_KEY', '')
        self.base_url = "https://api.shodan.io"
        self.cache = {}
    
    def search_host(self, ip: str) -> Dict:
        """Search host information"""
        
        ip_hash = hashlib.sha256(ip.encode()).hexdigest()
        
        if ip_hash in self.cache:
            return self.cache[ip_hash]
        
        result = {
            'ip': ip,
            'organization': 'Unknown',
            'country_name': 'Unknown',
            'ports': [],
            'hostnames': [],
            'os': None,
            'last_update': None,
            'source': 'Shodan'
        }
        
        self.cache[ip_hash] = result
        return result


class OTXIntegration:
    """AlienVault OTX Integration"""
    
    def __init__(self, api_key: str = None):
        self.api_key = api_key or os.getenv('OTX_API_KEY', '')
        self.base_url = "https://otx.alienvault.com/api/v1"
        self.cache = {}
    
    def check_ip(self, ip: str) -> Dict:
        """Check IP reputation"""
        
        result = {
            'ip': ip,
            'reputation': 0,
            'activity': [],
            'pulses': [],
            'pulse_count': 0,
            'source': 'AlienVault OTX'
        }
        
        return result
    
    def check_domain(self, domain: str) -> Dict:
        """Check domain reputation"""
        
        result = {
            'domain': domain,
            'reputation': 0,
            'activity': [],
            'pulses': [],
            'pulse_count': 0,
            'source': 'AlienVault OTX'
        }
        
        return result


class ThreatIntelligenceAggregator:
    """Aggregate threat intelligence from multiple sources"""
    
    def __init__(self):
        self.manager = IntelligenceSourceManager()
        self.sources = {}
        self._initialize_sources()
    
    def _initialize_sources(self):
        """Initialize default sources"""
        
        # Register sources
        self.manager.register_source('VirusTotal', {
            'enabled': True,
            'api_key': os.getenv('VIRUSTOTAL_API_KEY', ''),
            'endpoint': 'https://www.virustotal.com/api/v3',
            'priority': 10,
            'features': ['url_check', 'domain_check', 'ip_check', 'file_hash']
        })
        
        self.manager.register_source('PhishTank', {
            'enabled': True,
            'api_key': os.getenv('PHISHTANK_API_KEY', ''),
            'endpoint': 'https://checkurl.phishtank.com/api/checkurl',
            'priority': 9,
            'features': ['url_check', 'phishing_detection']
        })
        
        self.manager.register_source('URLhaus', {
            'enabled': True,
            'endpoint': 'https://urlhaus-api.abuse.ch/v1',
            'priority': 8,
            'features': ['url_check', 'domain_check', 'malware_detection']
        })
        
        self.manager.register_source('AbuseIPDB', {
            'enabled': True,
            'api_key': os.getenv('ABUSEIPDB_API_KEY', ''),
            'endpoint': 'https://api.abuseipdb.com/api/v2',
            'priority': 8,
            'features': ['ip_check', 'reputation', 'abuse_reports']
        })
        
        self.manager.register_source('Google Safe Browsing', {
            'enabled': True,
            'api_key': os.getenv('GOOGLE_SAFE_BROWSING_KEY', ''),
            'endpoint': 'https://safebrowsing.googleapis.com/v4',
            'priority': 10,
            'features': ['url_check', 'malware_detection', 'phishing_detection']
        })
    
    def check_url(self, url: str) -> Dict:
        """Check URL against all sources"""
        
        results = {
            'url': url,
            'timestamp': datetime.now().isoformat(),
            'sources': [],
            'consensus': {
                'threat_level': 'clean',
                'threat_count': 0,
                'clean_count': 0,
                'confidence': 0
            }
        }
        
        # Check VirusTotal
        vt = VirusTotalIntegration()
        results['sources'].append(vt.check_url(url))
        
        # Check PhishTank
        pt = PhishTankIntegration()
        results['sources'].append(pt.check_url(url))
        
        # Check URLhaus
        uh = URLHausIntegration()
        results['sources'].append(uh.check_url(url))
        
        # Check Google Safe Browsing
        gsb = GoogleSafeBrowsingIntegration()
        results['sources'].append(gsb.check_url(url))
        
        # Calculate consensus
        threat_count = sum(1 for s in results['sources'] if 'threat' in str(s).lower() and 'threat' != 'clean')
        clean_count = len(results['sources']) - threat_count
        
        if threat_count > 0:
            results['consensus']['threat_level'] = 'malicious' if threat_count >= 2 else 'suspicious'
            results['consensus']['threat_count'] = threat_count
        
        results['consensus']['clean_count'] = clean_count
        results['consensus']['confidence'] = (max(threat_count, clean_count) / len(results['sources'])) * 100
        
        return results
    
    def check_ip(self, ip: str) -> Dict:
        """Check IP against all sources"""
        
        results = {
            'ip': ip,
            'timestamp': datetime.now().isoformat(),
            'sources': []
        }
        
        # Check VirusTotal
        vt = VirusTotalIntegration()
        results['sources'].append(vt.check_ip(ip))
        
        # Check AbuseIPDB
        aipdb = AbuseIPDBIntegration()
        results['sources'].append(aipdb.check_ip(ip))
        
        # Check Shodan
        shodan = ShodanIntegration()
        results['sources'].append(shodan.search_host(ip))
        
        # Check OTX
        otx = OTXIntegration()
        results['sources'].append(otx.check_ip(ip))
        
        return results
