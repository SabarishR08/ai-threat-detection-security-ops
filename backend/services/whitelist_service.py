"""
Whitelist Service - Manages domains and URLs to exclude from threat detection
Prevents false positives for known safe services and user-trusted domains
"""

import json
import os
import logging
from typing import Dict, List, Set
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# Path to whitelist storage
WHITELIST_FILE = os.path.join(
    os.path.dirname(__file__), "..", "instance", "whitelist.json"
)


class WhitelistService:
    """Manage domain and URL whitelists"""
    
    # Built-in safe domains (legitimate services often flagged as false positives)
    BUILTIN_SAFE_DOMAINS = {
        # Major platforms & services
        "github.com",
        "github.io",
        "gitlab.com",
        "bitbucket.org",
        "google.com",
        "google.com.br",
        "google.de",
        "google.fr",
        "google.it",
        "google.es",
        "microsoft.com",
        "apple.com",
        "amazon.com",
        "facebook.com",
        "instagram.com",
        "twitter.com",
        "x.com",
        "linkedin.com",
        "youtube.com",
        "reddit.com",
        "stackoverflow.com",
        "wikipedia.org",
        "wordpress.com",
        
        # Development & tools
        "npmjs.com",
        "npm.org",
        "pypi.org",
        "maven.apache.org",
        "docker.com",
        "dockerhub.com",
        "kubernetes.io",
        "aws.amazon.com",
        "azure.microsoft.com",
        "cloud.google.com",
        "heroku.com",
        
        # Communication & collaboration
        "slack.com",
        "discord.com",
        "telegram.org",
        "whatsapp.com",
        "whatsapp.net",
        "messenger.com",
        "teams.microsoft.com",
        "zoom.us",
        "meet.google.com",
        
        # Email & productivity
        "gmail.com",
        "googlemail.com",
        "outlook.com",
        "outlook.live.com",
        "officeapps.live.com",
        "sharepoint.com",
        "onedrive.com",
        "dropbox.com",
        
        # Threat intel services (meta - don't flag tools that detect threats!)
        "phishtank.com",
        "phishtank.org",
        "checkurl.phishtank.com",
        "virustotal.com",
        "malwarebytes.com",
        "abuseipdb.com",
        "threatstream.com",
        "shodan.io",
        "urlhaus.abuse.ch",
        "openphish.com",
        
        # Security vendors
        "kaspersky.com",
        "avg.com",
        "avast.com",
        "mcafee.com",
        "symantec.com",
        "norton.com",
        "sophos.com",
        
        # Financial & e-commerce (commonly spoofed but actual services should pass)
        "paypal.com",
        "stripe.com",
        "square.com",
        "braintree.com",
        "2checkout.com",
        
        # News & media
        "bbc.co.uk",
        "cnn.com",
        "nytimes.com",
        "theguardian.com",
        "reuters.com",
        "apnews.com",
    }
    
    def __init__(self):
        """Initialize whitelist service"""
        self.user_whitelist = self._load_user_whitelist()
    
    @staticmethod
    def _load_user_whitelist() -> Set[str]:
        """Load user-configured whitelist from file"""
        try:
            if os.path.exists(WHITELIST_FILE):
                with open(WHITELIST_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    domains = set(data.get("domains", []))
                    # Normalize to lowercase
                    return {d.lower().strip() for d in domains if d}
        except Exception as e:
            logger.error(f"Failed to load whitelist: {e}")
        return set()
    
    @staticmethod
    def _save_user_whitelist(domains: Set[str]) -> bool:
        """Save user-configured whitelist to file"""
        try:
            os.makedirs(os.path.dirname(WHITELIST_FILE), exist_ok=True)
            with open(WHITELIST_FILE, "w", encoding="utf-8") as f:
                json.dump({
                    "domains": sorted(list(domains)),
                    "updated": True
                }, f, indent=2)
            return True
        except Exception as e:
            logger.error(f"Failed to save whitelist: {e}")
            return False
    
    def is_whitelisted_domain(self, domain: str) -> bool:
        """
        Check if a domain is whitelisted (built-in or user-configured)
        
        Args:
            domain: Domain to check (e.g., "github.com")
        
        Returns:
            True if domain is whitelisted, False otherwise
        """
        if not domain:
            return False
        
        domain = domain.lower().strip()
        
        # Check built-in safe domains
        if domain in self.BUILTIN_SAFE_DOMAINS:
            return True
        
        # Check for subdomain matches (e.g., api.github.com matches github.com)
        for safe_domain in self.BUILTIN_SAFE_DOMAINS:
            if domain == safe_domain or domain.endswith("." + safe_domain):
                return True
        
        # Check user whitelist
        if domain in self.user_whitelist:
            return True
        
        # Check for subdomain matches in user list
        for user_domain in self.user_whitelist:
            if domain == user_domain or domain.endswith("." + user_domain):
                return True
        
        return False
    
    def is_whitelisted_url(self, url: str) -> bool:
        """
        Check if a URL's domain is whitelisted
        
        Args:
            url: Full URL to check
        
        Returns:
            True if URL's domain is whitelisted
        """
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            return self.is_whitelisted_domain(domain)
        except Exception as e:
            logger.error(f"Error parsing URL {url}: {e}")
            return False
    
    def add_to_whitelist(self, domain: str) -> bool:
        """
        Add a domain to user whitelist
        
        Args:
            domain: Domain to add (e.g., "trusted.com")
        
        Returns:
            True if successful
        """
        domain = domain.lower().strip()
        
        if not domain or "." not in domain:
            logger.warning(f"Invalid domain format: {domain}")
            return False
        
        self.user_whitelist.add(domain)
        return self._save_user_whitelist(self.user_whitelist)
    
    def remove_from_whitelist(self, domain: str) -> bool:
        """
        Remove a domain from user whitelist
        
        Args:
            domain: Domain to remove
        
        Returns:
            True if successful
        """
        domain = domain.lower().strip()
        
        if domain in self.user_whitelist:
            self.user_whitelist.remove(domain)
            return self._save_user_whitelist(self.user_whitelist)
        
        return False
    
    def get_all_whitelisted_domains(self) -> Dict[str, List[str]]:
        """
        Get all whitelisted domains (built-in and user)
        
        Returns:
            Dict with 'builtin' and 'user' lists
        """
        return {
            "builtin": sorted(list(self.BUILTIN_SAFE_DOMAINS)),
            "user": sorted(list(self.user_whitelist)),
        }
    
    def clear_user_whitelist(self) -> bool:
        """Clear all user-configured whitelist entries"""
        self.user_whitelist = set()
        return self._save_user_whitelist(self.user_whitelist)
    
    def reset_to_builtin(self) -> bool:
        """Reset to only built-in whitelist (clear user entries)"""
        return self.clear_user_whitelist()


# Singleton instance
_instance = None


def get_whitelist_service() -> WhitelistService:
    """Get or create whitelist service singleton"""
    global _instance
    if _instance is None:
        _instance = WhitelistService()
    return _instance
