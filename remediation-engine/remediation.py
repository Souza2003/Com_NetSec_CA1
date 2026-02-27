import os
import json
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler

AUDIT_LOG = '/audit-log/actions.log'

PLAYBOOKS = {
    'isolate_host': {
        'description': 'Block suspicious IP via firewall',
        'command': 'iptables -A INPUT -s {src_ip} -j DROP',
        'rollback': 'iptables -D INPUT -s {src_ip} -j DROP',
        'requires_approval': True
    },
    'disable_account': {
        'description': 'Lock compromised user account',
        'command': 'usermod -L {username}',
        'rollback': 'usermod -U {username}',
        'requires_approval': True
    },
    'alert_only': {
        'description': 'Log alert for human review',
        'command': 'echo "Alert logged"',
        'rollback': 'N/A',
        'requires_approval': False
    }
}

def log_audit(message):
    timestamp = datetime.utcnow().isoformat()
    entry = f"[{timestamp}] REMEDIATION: {message}\n"
    with open(AUDIT_LOG, 'a') as f:
        f.write(entry)
    print(entry.strip())

class RemediationHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path == '/remediate':
            length = int(self.headers['Content-Length'])
            body = json.loads(self.rfile.read(length))

            action = body.get('action', 'alert_only')
            agent = body.get('agent_name', 'unknown')
            src_ip = body.get('src_ip', '0.0.0.0')
            username = body.get('username', 'unknown')
            severity = body.get('severity', 0)
            ai_summary = body.get('ai_summary', '')

            if action not in PLAYBOOKS:
                action = 'alert_only'

            playbook = PLAYBOOKS[action]
            command = playbook['command'].format(src_ip=src_ip, username=username)
            rollback = playbook['rollback'].format(src_ip=src_ip, username=username)

            log_audit(f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
            log_audit(f"Received action request from alert-processor")
            log_audit(f"Agent: {agent} | Severity: {severity} | Action: {action}")
            log_audit(f"AI Summary: {ai_summary[:100]}...")
            log_audit(f"Playbook: {playbook['description']}")
            log_audit(f"Command (SIMULATED): {command}")
            log_audit(f"Rollback available: {rollback}")
            log_audit(f"Requires human approval: {playbook['requires_approval']}")
            log_audit(f"Status: SIMULATED — awaiting human approval before live execution")

            response = {
                "status": "simulated",
                "action_taken": playbook['description'],
                "command": f"[SIMULATED] {command}",
                "rollback": rollback,
                "requires_approval": playbook['requires_approval'],
                "timestamp": datetime.utcnow().isoformat()
            }

            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(response).encode())

    def log_message(self, format, *args):
        pass  # suppress default HTTP logs

if __name__ == '__main__':
    os.makedirs('/audit-log', exist_ok=True)
    log_audit("Remediation Engine started — listening on port 5000")
    log_audit(f"Registered playbooks: {list(PLAYBOOKS.keys())}")
    server = HTTPServer(('0.0.0.0', 5000), RemediationHandler)
    server.serve_forever()
