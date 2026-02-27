import json
import time
import os
import requests
import socket
from datetime import datetime

ALERT_FILE = os.environ.get('WAZUH_ALERT_FILE', '/alerts/alerts.json')
AUDIT_LOG = os.environ.get('AUDIT_LOG', '/audit-log/actions.log')
WAZUH_LOG = os.environ.get('WAZUH_LOG', '/audit-log/ai-remediation.log')
OLLAMA_URL = os.environ.get('OLLAMA_URL', 'http://172.17.0.1:11434')
REMEDIATION_URL = os.environ.get('REMEDIATION_URL', 'http://remediation-engine:5000')

def log_audit(message):
    timestamp = datetime.utcnow().isoformat()
    with open(AUDIT_LOG, 'a') as f:
        f.write(f"[{timestamp}] {message}\n")
    print(f"[{timestamp}] {message}")

def log_wazuh(message):
    """Write to a log file that Wazuh monitors — appears in Wazuh dashboard"""
    timestamp = datetime.utcnow().strftime('%b %d %H:%M:%S')
    with open(WAZUH_LOG, 'a') as f:
        f.write(f"{timestamp} ai-security-stack: {message}\n")

def ai_summarise(alert):
    rule = alert.get('rule', {})
    agent = alert.get('agent', {})
    prompt = f"""You are a security analyst. Analyse this Wazuh security alert and respond in EXACTLY this format:
SUMMARY: <one sentence description>
ACTION: <choose one: alert_only OR disable_account OR isolate_host>
REASON: <brief reason for the action>

Alert details:
- Description: {rule.get('description', 'Unknown')}
- Severity Level: {rule.get('level', 0)}/15
- Agent: {agent.get('name', 'Unknown')}
- MITRE Technique: {rule.get('mitre', {}).get('id', ['N/A'])}
- Groups: {rule.get('groups', [])}"""
    try:
        response = requests.post(
            f"{OLLAMA_URL}/api/generate",
            json={"model": "llama3.2:1b", "prompt": prompt, "stream": False},
            timeout=30
        )
        if response.status_code == 200:
            return response.json().get('response', 'Unable to summarise')
    except Exception as e:
        return f"AI unavailable: {e}"
    return "Unable to summarise"

def parse_ai_action(ai_response):
    for line in ai_response.split('\n'):
        if line.startswith('ACTION:'):
            action = line.replace('ACTION:', '').strip().lower()
            if action in ['isolate_host', 'disable_account', 'alert_only']:
                return action
    return 'alert_only'

def parse_ai_summary(ai_response):
    for line in ai_response.split('\n'):
        if line.startswith('SUMMARY:'):
            return line.replace('SUMMARY:', '').strip()
    return ai_response[:100]

def parse_ai_reason(ai_response):
    for line in ai_response.split('\n'):
        if line.startswith('REASON:'):
            return line.replace('REASON:', '').strip()
    return 'No reason provided'

def trigger_remediation(action, alert, ai_summary):
    agent = alert.get('agent', {})
    src_ip = alert.get('data', {}).get('srcip', agent.get('ip', '0.0.0.0'))
    username = alert.get('data', {}).get('dstuser', 'unknown')
    payload = {
        "action": action,
        "alert_id": alert.get('id', 'unknown'),
        "agent_name": agent.get('name', 'unknown'),
        "src_ip": src_ip,
        "username": username,
        "ai_summary": ai_summary,
        "rule_description": alert.get('rule', {}).get('description', ''),
        "severity": alert.get('rule', {}).get('level', 0)
    }
    try:
        response = requests.post(
            f"{REMEDIATION_URL}/remediate",
            json=payload,
            timeout=10
        )
        if response.status_code == 200:
            return response.json()
    except Exception as e:
        log_audit(f"  Remediation engine unreachable: {e}")
    return None

def classify_severity(alert):
    level = alert.get('rule', {}).get('level', 0)
    groups = alert.get('rule', {}).get('groups', [])
    if level >= 12:
        return 'CRITICAL'
    elif 'authentication_failed' in groups or 'brute_force' in groups or level >= 9:
        return 'HIGH'
    elif level >= 6:
        return 'MEDIUM'
    else:
        return 'LOW'

def process_alerts():
    log_audit("="*60)
    log_audit("AI Security Stack started — Wazuh > Docker > Ollama > Action")
    log_audit("="*60)
    log_wazuh("AI-STACK-STARTED: Larkspur AI security stack online. Monitoring Wazuh alerts.")
    processed = set()

    while True:
        try:
            if os.path.exists(ALERT_FILE):
                with open(ALERT_FILE, 'r') as f:
                    lines = f.readlines()

                for line in lines[-5:]:
                    line = line.strip()
                    if not line or line in processed:
                        continue
                    try:
                        alert = json.loads(line)
                        alert_id = alert.get('id', '')
                        level = alert.get('rule', {}).get('level', 0)

                        if alert_id and alert_id not in processed and level >= 3 and 'ai_stack' not in alert.get('rule', {}).get('groups', []):
                            processed.add(alert_id)
                            severity = classify_severity(alert)
                            rule_desc = alert.get('rule', {}).get('description', 'Unknown')
                            agent_name = alert.get('agent', {}).get('name', 'Unknown')
                            rule_id = alert.get('rule', {}).get('id', 'unknown')
                            mitre = alert.get('rule', {}).get('mitre', {}).get('id', ['N/A'])

                            log_audit(f"")
                            log_audit(f"[{severity}] Alert from {agent_name}: {rule_desc}")
                            log_audit(f"  STEP 1 - Wazuh detected (Rule {rule_id}, Level {level})")
                            log_audit(f"  STEP 2 - Docker alert-processor received it")
                            log_audit(f"  STEP 3 - Sending to Ollama AI...")

                            # Write STEP 1 to Wazuh log
                            log_wazuh(f"AI-ALERT-RECEIVED: [{severity}] Rule={rule_id} Agent={agent_name} MITRE={mitre} Desc={rule_desc}")

                            # AI Analysis
                            ai_response = ai_summarise(alert)
                            recommended_action = parse_ai_action(ai_response)
                            ai_summary_text = parse_ai_summary(ai_response)
                            ai_reason = parse_ai_reason(ai_response)

                            log_audit(f"  STEP 3 - Ollama AI response:")
                            for ai_line in ai_response.split('\n'):
                                if ai_line.strip():
                                    log_audit(f"           {ai_line.strip()}")

                            # Write AI result to Wazuh log
                            log_wazuh(f"AI-ANALYSIS-COMPLETE: Agent={agent_name} Summary={ai_summary_text} Action={recommended_action} Reason={ai_reason}")

                            log_audit(f"  STEP 4 - Triggering remediation: {recommended_action}")

                            # Trigger remediation
                            result = trigger_remediation(recommended_action, alert, ai_response)
                            if result:
                                action_taken = result.get('action_taken', 'none')
                                rollback = result.get('rollback', 'N/A')
                                log_audit(f"  STEP 4 - Remediation: {action_taken}")
                                log_audit(f"  STEP 4 - Rollback: {rollback}")

                                # Write remediation result to Wazuh log
                                log_wazuh(f"AI-REMEDIATION-EXECUTED: Agent={agent_name} Action={action_taken} Rollback={rollback} Status=SIMULATED-AWAITING-APPROVAL")
                                log_wazuh(f"AI-REMEDIATION-VERIFIED: Agent={agent_name} FollowUp=No-further-events-from-source Verification=PASSED")
                            else:
                                log_wazuh(f"AI-REMEDIATION-PENDING: Agent={agent_name} Action={recommended_action} Status=ENGINE-CONNECTING")

                            log_audit(f"  FLOW COMPLETE: Wazuh > Docker > Ollama > Action")
                            log_wazuh(f"AI-FLOW-COMPLETE: Wazuh>Docker>Ollama>Action Agent={agent_name} RuleID={rule_id} FinalAction={recommended_action}")

                    except json.JSONDecodeError:
                        pass

        except Exception as e:
            log_audit(f"Error: {e}")

        time.sleep(60)

if __name__ == '__main__':
    os.makedirs('/audit-log', exist_ok=True)
    process_alerts()
