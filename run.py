#!/usr/bin/env python3
import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from app import create_app
import threading

app = create_app()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_DEBUG', '1') == '1'

    from scheduler import start_scheduler
    start_scheduler()

    print(f'[*] VulnForge running on http://0.0.0.0:{port}')
    print(f'[*] OpenCode agent integration: ~/.config/opencode')
    print(f'[*] Dashboard: http://localhost:{port}/dashboard')
    print(f'[*] Register: http://localhost:{port}/auth/register')

    app.run(host='0.0.0.0', port=port, debug=debug)
