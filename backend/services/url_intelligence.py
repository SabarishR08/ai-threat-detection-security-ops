"""
Advanced URL Preprocessing & Intelligence Service

Normalize, unshorten, extract components, detect threats
"""

import re
import logging
import requests
from urllib.parse import urlparse, parse_qs, unquote
from datetime import datetime
import whois
from typing import Dict, List, Tuple

logger = logging.getLogger(__name__)


class URLPreprocessor:
    """Preprocess and normalize URLs"""
    
    @staticmethod
    def normalize_url(url: str) -> str:
        """Normalize URL for consistent analysis"""
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        url = url.strip()
        
        # Remove trailing slash for consistency
        if url.endswith('/') and url.count('/') > 3:
            url = url.rstrip('/')
        
        # Remove common tracking parameters
        tracking_params = [
            'utm_source', 'utm_medium', 'utm_campaign', 'utm_content', 'utm_term',
            'fbclid', 'gclid', 'msclkid', 'ptaid', 'ref'
        ]
        
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        
        # Remove tracking params
        for param in tracking_params:
            params.pop(param, None)
        
        # Reconstruct query string
        new_query = '&'.join(f"{k}={v[0]}" for k, v in params.items())
        
        if new_query:
            url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
        else:
            url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        
        return url
    
    @staticmethod
    def extract_components(url: str) -> Dict:
        """Extract URL components"""
        parsed = urlparse(url)
        
        # Extract domain parts
        domain = parsed.netloc
        domain_parts = domain.split('.')
        
        return {
            'original_url': url,
            'scheme': parsed.scheme,
            'domain': domain,
            'subdomain': '.'.join(domain_parts[:-2]) if len(domain_parts) > 2 else '',
            'domain_name': domain_parts[-2] if len(domain_parts) >= 2 else '',
            'tld': domain_parts[-1] if domain_parts else '',
            'ip': None,  # Will be extracted separately
            'port': parsed.port,
            'path': parsed.path,
            'query_params': parse_qs(parsed.query),
            'fragment': parsed.fragment
        }
    
    @staticmethod
    def unshorten_url(url: str, timeout=5) -> str:
        """
        Unshorten shortened URLs
        
        Returns final destination URL
        """
        shorteners = ['bit.ly', 'tinyurl.com', 'short.link', 'ow.ly', 'buff.ly', 'snip.ly']
        
        parsed = urlparse(url)
        if not any(shortener in parsed.netloc for shortener in shorteners):
            return url
        
        try:
            response = requests.head(url, allow_redirects=True, timeout=timeout, verify=False)
            return response.url
        except Exception as e:
            logger.warning(f"Failed to unshorten URL: {e}")
            return url
    
    @staticmethod
    def extract_all_urls(text: str) -> List[str]:
        """Extract all URLs from text"""
        url_pattern = r'https?://[^\s\)<>\[\]"\']+|www\.[^\s\)<>\[\]"\']+\.[a-z]{2,}'
        urls = re.findall(url_pattern, text, re.IGNORECASE)
        
        # Add https:// to www URLs
        return [url if url.startswith('http') else f'https://{url}' for url in urls]
    
    @staticmethod
    def has_redirect_chain(url: str, timeout=5) -> Tuple[bool, List[str]]:
        """
        Check if URL has redirect chain
        
        Returns: (has_redirects, [chain of URLs])
        """
        chain = [url]
        try:
            response = requests.head(url, allow_redirects=False, timeout=timeout, verify=False)
            
            while 300 <= response.status_code < 400:
                redirect_url = response.headers.get('location')
                if not redirect_url:
                    break
                
                # Handle relative redirects
                if not redirect_url.startswith('http'):
                    parsed = urlparse(chain[-1])
                    redirect_url = f"{parsed.scheme}://{parsed.netloc}{redirect_url}"
                
                chain.append(redirect_url)
                response = requests.head(redirect_url, allow_redirects=False, timeout=timeout, verify=False)
            
            return len(chain) > 1, chain
        except Exception as e:
            logger.warning(f"Redirect check error: {e}")
            return False, [url]


class URLThreatDetector:
    """Detect threats in URLs"""
    
    # Suspicious TLDs
    SUSPICIOUS_TLDS = ['tk', 'ml', 'ga', 'cf', 'download', 'review', 'zip', 'click']
    
    # Known malicious patterns
    MALICIOUS_PATTERNS = [
        r'cmd=.*&',  # Command injection
        r'exec\(',   # Code execution
        r'eval\(',   # JavaScript eval
        r'system\(', # System command
        r'base64_decode',  # Encoded payload
    ]
    
    # Homoglyph mappings
    HOMOGLYPH_MAP = {
        'a': ['а', 'ɑ', 'ⅰ'],  # Cyrillic 'a'
        'e': ['е', 'ê', 'ё'],    # Cyrillic 'e'
        'o': ['о', 'ⅰ'],         # Cyrillic 'o'
    }
    
    @staticmethod
    def detect_threats(url: str) -> Dict:
        """
        Detect threats in URL
        
        Returns: {threats: [], risk_level: '', risk_score: 0}
        """
        threats = []
        risk_score = 0
        
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        path = parsed.path.lower()
        query = parsed.query.lower()
        
        # 1. Check for IP-based URL
        if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain):
            threats.append('IP-based URL (no domain)')
            risk_score += 25
        
        # 2. Check for suspicious TLD
        tld = domain.split('.')[-1]
        if tld in URLThreatDetector.SUSPICIOUS_TLDS:
            threats.append(f'Suspicious TLD: .{tld}')
            risk_score += 20
        
        # 3. Check for very new domain
        try:
            domain_info = whois.whois(domain)
            if domain_info.creation_date:
                creation = domain_info.creation_date
                if isinstance(creation, list):
                    creation = creation[0]
                
                days_old = (datetime.now() - creation).days
                if days_old < 30:
                    threats.append(f'Recently registered domain ({days_old} days old)')
                    risk_score += 30
                elif days_old < 365:
                    threats.append(f'Young domain ({days_old} days old)')
                    risk_score += 15
        except Exception as e:
            logger.debug(f"WHOIS lookup failed: {e}")
        
        # 4. Check for homoglyph attack
        if URLThreatDetector._has_homoglyph(domain):
            threats.append('Potential homoglyph attack (look-alike domain)')
            risk_score += 35
        
        # 5. Check for punycode
        if 'xn--' in domain:
            threats.append('Punycode domain (potential spoofing)')
            risk_score += 30
        
        # 6. Check for excessive subdomains
        if domain.count('.') > 3:
            threats.append('Excessive subdomains (suspicious)')
            risk_score += 15
        
        # 7. Check for long domain
        if len(domain) > 50:
            threats.append('Unusually long domain')
            risk_score += 10
        
        # 8. Check for encoded URL segments
        if '%' in url and any(keyword in unquote(url).lower() for keyword in ['login', 'password', 'admin']):
            threats.append('Encoded suspicious keywords in URL')
            risk_score += 25
        
        # 9. Check for malicious patterns
        for pattern in URLThreatDetector.MALICIOUS_PATTERNS:
            if re.search(pattern, url, re.IGNORECASE):
                threats.append(f'Malicious pattern detected: {pattern}')
                risk_score += 30
        
        # 10. Check for auto-download indicators
        download_extensions = ['.exe', '.msi', '.dmg', '.zip', '.rar', '.bat', '.scr']
        if any(url.endswith(ext) for ext in download_extensions):
            threats.append('Direct executable download')
            risk_score += 40
        
        # 11. Check for phishing keywords in path
        phishing_keywords = ['login', 'verify', 'confirm', 'update', 'secure', 'account']
        if any(keyword in path for keyword in phishing_keywords):
            threats.append('Phishing keywords in URL path')
            risk_score += 20
        
        # 12. Check for TOR/Onion
        if '.onion' in domain:
            threats.append('TOR onion address')
            risk_score += 50
        
        # 13. Check for data URI
        if url.startswith('data:'):
            threats.append('Data URI (embedded content)')
            risk_score += 15
        
        return {
            'threats': threats,
            'risk_level': 'low' if risk_score < 33 else 'medium' if risk_score < 66 else 'high',
            'risk_score': min(risk_score, 100)
        }
    
    @staticmethod
    def _has_homoglyph(domain: str) -> bool:
        """Check for homoglyph characters"""
        for char in domain:
            if char in 'абвгдежзийклмнопрстуфхцчшщъыьэюяАБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ':
                return True
        
        return False
    
    @staticmethod
    def check_reputation(domain: str) -> Dict:
        """
        Check domain reputation from multiple sources
        
        Returns: {reputable: bool, sources: {source: status}}
        """
        reputation = {
            'reputable': True,
            'sources': {}
        }
        
        # Would integrate with: PhishTank, URLHaus, etc.
        # For now, basic check
        
        suspicious_domains = ['bit.ly', 'tinyurl', 'pastebin', 'zerobin']
        if any(susp in domain for susp in suspicious_domains):
            reputation['reputable'] = False
            reputation['sources']['url_shortener'] = 'suspicious'
        
        return reputation


class URLAnalyzer:
    """Combined URL analysis"""
    
    @staticmethod
    def full_analysis(url: str) -> Dict:
        """
        Complete URL analysis
        
        Returns comprehensive threat report
        """
        # Normalize
        url = URLPreprocessor.normalize_url(url)
        
        # Extract components
        components = URLPreprocessor.extract_components(url)
        
        # Unshorten
        final_url = URLPreprocessor.unshorten_url(url)
        has_redirects, redirect_chain = URLPreprocessor.has_redirect_chain(url)
        
        # Detect threats
        threats = URLThreatDetector.detect_threats(final_url)
        
        # Check reputation
        reputation = URLThreatDetector.check_reputation(components['domain'])
        
        return {
            'original_url': url,
            'final_url': final_url,
            'components': components,
            'has_redirects': has_redirects,
            'redirect_chain': redirect_chain,
            'threats': threats['threats'],
            'risk_level': threats['risk_level'],
            'risk_score': threats['risk_score'],
            'reputation': reputation,
            'analysis_timestamp': datetime.now().isoformat()
        }
