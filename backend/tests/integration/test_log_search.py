#!/usr/bin/env python
import sys
sys.path.insert(0, 'backend')

from app import app

def main() -> None:
    with app.test_client() as client:
        with client.session_transaction() as sess:
            sess['settings_authenticated'] = True

        response = client.post('/api/logs/search', 
            json={'query': 'whatsapp'},
            follow_redirects=True
        )

        print(f"Status code: {response.status_code}")

        if response.status_code == 200:
            data = response.get_json()
            print(f"Found {len(data)} logs")
            if len(data) > 0:
                print(f"First log: {data[0]}")
        else:
            print(f"Error response: {response.get_json()}")


if __name__ == "__main__":
    main()
