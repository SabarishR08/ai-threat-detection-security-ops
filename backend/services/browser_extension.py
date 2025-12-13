"""
Browser Extension Enhancement - Real-time scanning, tab sandboxing, protection
"""

import json
from typing import Dict, List
import hashlib
from datetime import datetime


class TabSandbox:
    """Sandbox manager for browser tabs"""
    
    def __init__(self):
        self.sandboxed_tabs = {}
        self.protected_domains = set()
        self.url_whitelist = set()
        self.url_blacklist = set()
    
    def sandbox_tab(self, tab_id: int, url: str, reason: str = "Suspected malicious content") -> Dict:
        """Sandbox a tab"""
        
        sandbox_id = hashlib.md5(f"{tab_id}_{datetime.now().isoformat()}".encode()).hexdigest()
        
        self.sandboxed_tabs[tab_id] = {
            'sandbox_id': sandbox_id,
            'url': url,
            'reason': reason,
            'created_at': datetime.now().isoformat(),
            'actions_available': [
                'view_details',
                'whitelist_domain',
                'block_domain',
                'report_to_google',
                'close_tab'
            ]
        }
        
        return self.sandboxed_tabs[tab_id]
    
    def unsandbox_tab(self, tab_id: int) -> bool:
        """Remove tab from sandbox"""
        
        if tab_id in self.sandboxed_tabs:
            del self.sandboxed_tabs[tab_id]
            return True
        return False
    
    def whitelist_domain(self, domain: str) -> None:
        """Add domain to whitelist"""
        self.url_whitelist.add(domain)
    
    def blacklist_domain(self, domain: str) -> None:
        """Add domain to blacklist"""
        self.url_blacklist.add(domain)
    
    def is_whitelisted(self, domain: str) -> bool:
        """Check if domain is whitelisted"""
        return domain in self.url_whitelist
    
    def is_blacklisted(self, domain: str) -> bool:
        """Check if domain is blacklisted"""
        return domain in self.url_blacklist
    
    def get_sandboxed_tabs(self) -> Dict:
        """Get all sandboxed tabs"""
        return self.sandboxed_tabs.copy()


class RealTimeURLScanner:
    """Real-time URL scanning for browser"""
    
    def __init__(self):
        self.scan_history = []
        self.cached_results = {}
        self.pending_scans = {}
    
    def scan_url(self, url: str, tab_id: int = None) -> Dict:
        """Scan URL in real-time"""
        
        url_hash = hashlib.sha256(url.encode()).hexdigest()
        
        # Check cache
        if url_hash in self.cached_results:
            cached = self.cached_results[url_hash]
            if (datetime.now().isoformat() < cached.get('expires_at')):
                return cached
        
        scan_result = {
            'url': url,
            'tab_id': tab_id,
            'status': 'scanning',
            'timestamp': datetime.now().isoformat(),
            'expires_at': datetime.now().isoformat(),
            'threats': [],
            'risk_score': 0,
            'safe': True
        }
        
        self.pending_scans[url_hash] = scan_result
        return scan_result
    
    def update_scan_result(self, url: str, result: Dict) -> None:
        """Update scan result"""
        
        url_hash = hashlib.sha256(url.encode()).hexdigest()
        
        scan_result = {
            'url': url,
            'status': 'complete',
            'timestamp': datetime.now().isoformat(),
            **result
        }
        
        # Cache result for 24 hours
        from datetime import timedelta
        expires_at = (datetime.now() + timedelta(hours=24)).isoformat()
        scan_result['expires_at'] = expires_at
        
        self.cached_results[url_hash] = scan_result
        
        if url_hash in self.pending_scans:
            del self.pending_scans[url_hash]
        
        self.scan_history.append(scan_result)
    
    def get_scan_history(self, limit: int = 50) -> List[Dict]:
        """Get scan history"""
        return self.scan_history[-limit:]
    
    def get_pending_scans(self) -> Dict:
        """Get pending scans"""
        return self.pending_scans.copy()


class AutoProtection:
    """Automatic protection features"""
    
    def __init__(self):
        self.protection_rules = []
        self.blocked_domains = set()
        self.protection_level = 'medium'  # low, medium, high
        self.auto_block_enabled = True
        self.warning_popup_enabled = True
    
    def add_protection_rule(self, rule_type: str, pattern: str, action: str) -> Dict:
        """Add protection rule"""
        
        rule = {
            'id': hashlib.md5(f"{rule_type}_{pattern}_{datetime.now().isoformat()}".encode()).hexdigest(),
            'type': rule_type,  # domain, pattern, suspicious_keyword, malicious_extension
            'pattern': pattern,
            'action': action,  # block, warn, allow, sandbox
            'enabled': True,
            'created_at': datetime.now().isoformat()
        }
        
        self.protection_rules.append(rule)
        return rule
    
    def set_protection_level(self, level: str) -> None:
        """Set protection level"""
        if level in ['low', 'medium', 'high']:
            self.protection_level = level
    
    def get_protection_level(self) -> str:
        """Get current protection level"""
        return self.protection_level
    
    def block_domain(self, domain: str) -> None:
        """Block domain"""
        self.blocked_domains.add(domain)
    
    def unblock_domain(self, domain: str) -> None:
        """Unblock domain"""
        self.blocked_domains.discard(domain)
    
    def is_domain_blocked(self, domain: str) -> bool:
        """Check if domain is blocked"""
        return domain in self.blocked_domains
    
    def get_blocked_domains(self) -> List[str]:
        """Get all blocked domains"""
        return list(self.blocked_domains)
    
    def check_protection_rules(self, url: str) -> List[Dict]:
        """Check URL against protection rules"""
        
        matching_rules = []
        for rule in self.protection_rules:
            if rule['enabled'] and rule['pattern'] in url:
                matching_rules.append(rule)
        
        return matching_rules


class BrowserNotification:
    """Browser notification manager"""
    
    @staticmethod
    def create_notification(title: str, message: str, type: str = 'info',
                          icon: str = 'default', timeout: int = 5000) -> Dict:
        """Create browser notification"""
        
        notification = {
            'id': hashlib.md5(f"{title}_{datetime.now().isoformat()}".encode()).hexdigest(),
            'title': title,
            'message': message,
            'type': type,  # info, warning, danger, success
            'icon': icon,
            'timeout': timeout,
            'timestamp': datetime.now().isoformat(),
            'actions': []
        }
        
        # Add actions based on type
        if type == 'danger':
            notification['actions'] = [
                {'label': 'Block Domain', 'action': 'block_domain'},
                {'label': 'Report', 'action': 'report'},
                {'label': 'Dismiss', 'action': 'dismiss'}
            ]
        elif type == 'warning':
            notification['actions'] = [
                {'label': 'Learn More', 'action': 'learn_more'},
                {'label': 'Dismiss', 'action': 'dismiss'}
            ]
        
        return notification


class PermissionManager:
    """Manage extension permissions"""
    
    REQUIRED_PERMISSIONS = [
        'activeTab',
        'scripting',
        'webRequest',
        'webRequestBlocking',
        'tabs',
        'storage',
        'notifications'
    ]
    
    OPTIONAL_PERMISSIONS = [
        'history',
        'bookmarks',
        'downloads',
        'management'
    ]
    
    def __init__(self):
        self.granted_permissions = set()
        self.requested_permissions = set()
    
    def request_permission(self, permission: str) -> bool:
        """Request a permission"""
        
        if permission in self.REQUIRED_PERMISSIONS or permission in self.OPTIONAL_PERMISSIONS:
            self.requested_permissions.add(permission)
            return True
        return False
    
    def grant_permission(self, permission: str) -> None:
        """Grant a permission"""
        self.granted_permissions.add(permission)
        if permission in self.requested_permissions:
            self.requested_permissions.remove(permission)
    
    def has_permission(self, permission: str) -> bool:
        """Check if permission is granted"""
        return permission in self.granted_permissions
    
    def get_granted_permissions(self) -> List[str]:
        """Get all granted permissions"""
        return list(self.granted_permissions)
    
    def get_requested_permissions(self) -> List[str]:
        """Get pending permission requests"""
        return list(self.requested_permissions)


class ContextMenuManager:
    """Manage context menu items"""
    
    def __init__(self):
        self.menu_items = []
    
    def add_menu_item(self, title: str, action: str, contexts: List[str] = None,
                      parent_id: str = None) -> Dict:
        """Add context menu item"""
        
        menu_item = {
            'id': hashlib.md5(f"{title}_{datetime.now().isoformat()}".encode()).hexdigest(),
            'title': title,
            'action': action,
            'contexts': contexts or ['selection', 'link', 'image'],
            'parent_id': parent_id,
            'enabled': True
        }
        
        self.menu_items.append(menu_item)
        return menu_item
    
    def get_menu_items(self, context: str = None) -> List[Dict]:
        """Get menu items for context"""
        
        if context:
            return [item for item in self.menu_items if context in item['contexts']]
        return self.menu_items
    
    def remove_menu_item(self, menu_id: str) -> bool:
        """Remove menu item"""
        
        for i, item in enumerate(self.menu_items):
            if item['id'] == menu_id:
                self.menu_items.pop(i)
                return True
        return False


class StorageManager:
    """Local storage management for extension"""
    
    def __init__(self):
        self.local_storage = {}
        self.sync_storage = {}
    
    def set_local(self, key: str, value: any) -> None:
        """Set local storage value"""
        self.local_storage[key] = value
    
    def get_local(self, key: str, default=None) -> any:
        """Get local storage value"""
        return self.local_storage.get(key, default)
    
    def set_sync(self, key: str, value: any) -> None:
        """Set sync storage value"""
        self.sync_storage[key] = value
    
    def get_sync(self, key: str, default=None) -> any:
        """Get sync storage value"""
        return self.sync_storage.get(key, default)
    
    def clear_local(self) -> None:
        """Clear local storage"""
        self.local_storage.clear()
    
    def clear_sync(self) -> None:
        """Clear sync storage"""
        self.sync_storage.clear()
    
    def export_data(self) -> Dict:
        """Export all storage"""
        return {
            'local': self.local_storage.copy(),
            'sync': self.sync_storage.copy(),
            'exported_at': datetime.now().isoformat()
        }
