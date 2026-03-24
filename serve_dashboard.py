#!/usr/bin/env python3
"""
Simple HTTP server for the Attack Simulation Dashboard
Serves the dashboard and handles CORS for local development
"""

import http.server
import socketserver
import os

PORT = 8000

class DashboardHandler(http.server.SimpleHTTPRequestHandler):
    def end_headers(self):
        # Add CORS headers for local development
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Cache-Control', 'no-store, no-cache, must-revalidate')
        super().end_headers()

    def log_message(self, format, *args):
        # Cleaner log output
        if args[0].startswith('GET'):
            print(f"[REQUEST] {args[0]}")

if __name__ == "__main__":
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    
    with socketserver.TCPServer(("", PORT), DashboardHandler) as httpd:
        print("=" * 56)
        print("  Attack Simulation Dashboard Server")
        print("=" * 56)
        print(f"\nServer running at: http://localhost:{PORT}")
        print(f"Dashboard URL: http://localhost:{PORT}/dashboard.html\n")
        print("Press Ctrl+C to stop the server\n")
        
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n\nServer stopped")
