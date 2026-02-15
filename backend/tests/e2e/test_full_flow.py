#!/usr/bin/env python
import sys
sys.path.insert(0, 'backend')

from app import app

with app.test_client() as client:
    print("=== Testing Settings Authentication Flow ===\n")
    
    # Step 1: Try to access settings without auth (should redirect to login)
    print("Step 1: Access /settings without authentication")
    response = client.get('/settings')
    print(f"Status: {response.status_code}")
    print(f"Content length: {len(response.data)}")
    if b'Authenticate' in response.data:
        print("✓ Correctly showing login page\n")
    else:
        print("✗ Not showing login page\n")
    
    # Step 2: Authenticate
    print("Step 2: Authenticate with credentials")
    response = client.post('/api/settings/authenticate', 
        json={'username': 'admin', 'password': 'admin123'}
    )
    print(f"Status: {response.status_code}")
    data = response.get_json()
    print(f"Response: {data}\n")
    
    # Step 3: Access settings after auth
    print("Step 3: Access /settings with authentication")
    response = client.get('/settings')
    print(f"Status: {response.status_code}")
    if b'Manual Log Editor' in response.data:
        print("✓ Settings page loaded with log editor\n")
    else:
        print("✗ Settings page doesn't have log editor\n")
    
    # Step 4: Search logs
    print("Step 4: Search for logs")
    response = client.post('/api/logs/search', 
        json={'query': 'whatsapp'}
    )
    print(f"Status: {response.status_code}")
    data = response.get_json()
    if isinstance(data, list):
        print(f"✓ Found {len(data)} logs")
        if len(data) > 0:
            print(f"  First log: {data[0]['url']}")
    else:
        print(f"✗ Error: {data}\n")
    
    # Step 5: Update a log
    if isinstance(data, list) and len(data) > 0:
        print("\nStep 5: Update first log")
        log_id = data[0]['id']
        response = client.post('/api/logs/update', 
            json={
                'id': log_id,
                'status': 'Safe',
                'severity': 'Low',
                'flagged_reason': 'False positive - fixed'
            }
        )
        print(f"Status: {response.status_code}")
        result = response.get_json()
        print(f"Response: {result}")
        if result.get('success'):
            print("✓ Log updated successfully")
        else:
            print(f"✗ Failed to update: {result.get('error')}")
