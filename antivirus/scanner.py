import os
import hashlib
import requests

VT_API_KEY = '37c4213f50837f74c9767cf285d64a4fde69bb5422b1aedb28f4fff5df5df1f5'

class Scanner:
    def __init__(self, signature_db_path):
        self.signature_db_path = signature_db_path
        self.signatures = self.load_signatures()

    def load_signatures(self):
        # Load signatures (hash, virus_name) from DB file
        sigs = {}
        if os.path.exists(self.signature_db_path):
            with open(self.signature_db_path, 'r') as f:
                for line in f:
                    parts = line.strip().split(None, 1)
                    if len(parts) == 2:
                        sigs[parts[0]] = parts[1]
                    elif len(parts) == 1:
                        sigs[parts[0]] = 'Unknown'
        return sigs

    def hash_file(self, file_path):
        # Calculate SHA256 hash of a file
        try:
            hasher = hashlib.sha256()
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b''):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except Exception as e:
            return None

    def scan_file(self, file_path):
        file_hash = self.hash_file(file_path)
        if file_hash is None:
            return ('Error', '', None)
        if file_hash in self.signatures:
            return ('Infected', self.signatures[file_hash], None)
        # Not in local DB, check VirusTotal
        vt_details = self.check_virustotal(file_hash)
        if vt_details:
            return ('Infected', vt_details['virus_name'], vt_details)
        else:
            return ('Clean', '', None)

    def scan_folder(self, folder_path, return_hashes=False):
        results = {}
        for root, dirs, files in os.walk(folder_path):
            for name in files:
                file_path = os.path.join(root, name)
                file_hash = self.hash_file(file_path)
                if file_hash is None:
                    result = ('Error', '', None)
                elif file_hash in self.signatures:
                    result = ('Infected', self.signatures[file_hash], None)
                else:
                    vt_details = self.check_virustotal(file_hash)
                    if vt_details:
                        result = ('Infected', vt_details['virus_name'], vt_details)
                    else:
                        result = ('Clean', '', None)
                if return_hashes:
                    results[file_path] = (result[0], file_hash, result[1], result[2])
                else:
                    results[file_path] = result
        return results

    def check_virustotal(self, file_hash):
        try:
            url = f'https://www.virustotal.com/api/v3/files/{file_hash}'
            headers = {'x-apikey': VT_API_KEY}
            resp = requests.get(url, headers=headers, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                stats = data['data']['attributes']['last_analysis_stats']
                if stats['malicious'] > 0 or stats['suspicious'] > 0:
                    # Get the most common virus name and all details
                    names = []
                    engines = []
                    results = data['data']['attributes']['last_analysis_results']
                    for engine, result in results.items():
                        if result['category'] in ('malicious', 'suspicious') and result['result']:
                            names.append(result['result'])
                            engines.append(engine)
                    from collections import Counter
                    most_common = Counter(names).most_common(1)[0][0] if names else 'VirusTotal:Malicious'
                    detection_ratio = f"{stats['malicious']}/{sum(stats.values())}"
                    scan_date = data['data']['attributes'].get('last_analysis_date', None)
                    if scan_date:
                        import datetime
                        scan_date = datetime.datetime.fromtimestamp(scan_date).strftime('%Y-%m-%d')
                    permalink = f'https://www.virustotal.com/gui/file/{file_hash}'
                    return {
                        'virus_name': most_common,
                        'detection_ratio': detection_ratio,
                        'engines': engines,
                        'scan_date': scan_date,
                        'permalink': permalink,
                        'all_names': list(set(names)),
                    }
            return None
        except Exception:
            return None

    def quarantine(self, file_path):
        # Placeholder: Move file to quarantine
        pass

    def update_signatures(self):
        # Placeholder: Update signature DB
        pass 