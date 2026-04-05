#!/usr/bin/env python
import sys
sys.path.insert(0, 'backend')

from app import app

with app.test_client() as client:
    with client.session_transaction() as sess:
        sess['settings_authenticated'] = True
    resp = client.get('/settings')
    print(f'Status: {resp.status_code}')
    print(f'Content length: {len(resp.data)}')
    if b'Manual Log Editor' in resp.data:
        print('✓ Manual Log Editor section present in HTML')
    else:
        print('✗ Manual Log Editor section MISSING from HTML')
    if b'Alert Preferences' in resp.data:
        print('✓ Alert Preferences section present')
    else:
        print('✗ Alert Preferences section MISSING')
    if b'saveSettingsBtn' in resp.data:
        print('✓ Save Settings button present')
    else:
        print('✗ Save Settings button MISSING')
