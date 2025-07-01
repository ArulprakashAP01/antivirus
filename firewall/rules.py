import subprocess

class FirewallRules:
    def list_rules(self):
        # Use netsh to list all firewall rules for programs
        rules = []
        try:
            output = subprocess.check_output(
                ['netsh', 'advfirewall', 'firewall', 'show', 'rule', 'name=all'],
                stderr=subprocess.STDOUT, text=True, encoding='utf-8', errors='ignore')
            rule = {}
            for line in output.splitlines():
                line = line.strip()
                if line.startswith('Rule Name:'):
                    if rule:
                        rules.append(rule)
                    rule = {'name': line.split(':', 1)[1].strip()}
                elif line.startswith('Action:'):
                    rule['action'] = line.split(':', 1)[1].strip()
                elif line.startswith('Program:'):
                    rule['program'] = line.split(':', 1)[1].strip()
            if rule:
                rules.append(rule)
            # Only show rules with a program path
            return [f"{r.get('name','')} | {r.get('action','')} | {r.get('program','')}" for r in rules if r.get('program') and r.get('program') != 'Any']
        except Exception as e:
            return [f"Error: {e}"]

    def add_rule(self, name, app_path):
        # Allow an application through the firewall
        try:
            subprocess.check_call([
                'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                f'name={name}', 'dir=in', 'action=allow', f'program={app_path}', 'enable=yes'
            ])
            return True
        except Exception:
            return False

    def remove_rule(self, name):
        # Remove a firewall rule by name
        try:
            subprocess.check_call([
                'netsh', 'advfirewall', 'firewall', 'delete', 'rule', f'name={name}'
            ])
            return True
        except Exception:
            return False

    def block_app(self, app_path):
        # Block an application by path
        try:
            subprocess.check_call([
                'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                f'name=Block_{app_path}', 'dir=out', 'action=block', f'program={app_path}', 'enable=yes'
            ])
            return True
        except Exception:
            return False

    def unblock_app(self, app_path):
        # Remove all block rules for the given app path
        try:
            subprocess.check_call([
                'netsh', 'advfirewall', 'firewall', 'delete', 'rule', f'program={app_path}'
            ])
            return True
        except Exception:
            return False
