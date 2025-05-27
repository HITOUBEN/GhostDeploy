import yaml
import re
import json
import hashlib
import base64
import requests
import time
from urllib.parse import urlparse
from typing import Dict, List, Set, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
from rich import print
from rich.table import Table
from rich.panel import Panel
from rich.console import Console
from rich.progress import track, Progress

class SeverityLevel(Enum):
    CRITICAL = "🔴 CRITIQUE"
    HIGH = "🟠 ÉLEVÉ"
    MEDIUM = "🟡 MOYEN"
    LOW = "🟢 FAIBLE"
    INFO = "🔵 INFO"

@dataclass
class SecurityAnomaly:
    job: str
    step: str
    type: str
    detail: str
    severity: SeverityLevel
    category: str
    recommendation: str
    cwe_id: Optional[str] = None
    references: List[str] = None
    cve_matches: List[str] = None

class MultiVulnDatabase:
    """Intégrateur de plusieurs bases de vulnérabilités"""
    
    def __init__(self):
        self.console = Console()
        self.cve_cache = {}
        
        # Configuration des APIs
        self.apis = {
            'nvd': {
                'url': 'https://services.nvd.nist.gov/rest/json/cves/2.0',
                'headers': {'User-Agent': 'DevSecOps-Analyzer/1.0'}
            },
            'vulners': {
                'url': 'https://vulners.com/api/v3/search/lucene/',
                'headers': {'Content-Type': 'application/json'}
            },
            'cvedetails': {
                'url': 'https://www.cvedetails.com/json-feed.php',
                'headers': {'User-Agent': 'DevSecOps-Analyzer/1.0'}
            },
            'exploit_db': {
                'url': 'https://www.exploit-db.com/search',
                'headers': {'User-Agent': 'DevSecOps-Analyzer/1.0'}
            }
        }
    
    def search_nvd_cve(self, keyword: str) -> List[Dict]:
        """Recherche dans la base NVD (NIST)"""
        try:
            params = {
                'keywordSearch': keyword,
                'resultsPerPage': 10
            }
            response = requests.get(
                self.apis['nvd']['url'], 
                params=params,
                headers=self.apis['nvd']['headers'],
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                return data.get('vulnerabilities', [])
        except Exception as e:
            self.console.print(f"[yellow]Erreur NVD API: {e}[/yellow]")
        return []
    
    def search_vulners(self, keyword: str) -> List[Dict]:
        """Recherche dans Vulners.com"""
        try:
            query = {
                "query": f"title:{keyword} OR description:{keyword}",
                "size": 10,
                "sort": [{"field": "published", "order": "desc"}]
            }
            response = requests.post(
                self.apis['vulners']['url'],
                json=query,
                headers=self.apis['vulners']['headers'],
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('result') == 'OK':
                    return data.get('data', {}).get('documents', [])
        except Exception as e:
            self.console.print(f"[yellow]Erreur Vulners API: {e}[/yellow]")
        return []
    
    def get_vulnerability_info(self, software: str, version: str = None) -> List[Dict]:
        """Récupère les informations de vulnérabilité pour un logiciel"""
        search_term = f"{software} {version}" if version else software
        
        vulnerabilities = []
        
        # Recherche dans NVD
        nvd_results = self.search_nvd_cve(search_term)
        for vuln in nvd_results:
            cve_data = vuln.get('cve', {})
            vulnerabilities.append({
                'source': 'NVD',
                'id': cve_data.get('id', 'N/A'),
                'description': cve_data.get('descriptions', [{}])[0].get('value', 'N/A'),
                'severity': self._get_cvss_severity(cve_data.get('metrics', {})),
                'published': cve_data.get('published', 'N/A')
            })
        
        # Recherche dans Vulners
        vulners_results = self.search_vulners(search_term)
        for vuln in vulners_results:
            vulnerabilities.append({
                'source': 'Vulners',
                'id': vuln.get('id', 'N/A'),
                'description': vuln.get('description', 'N/A'),
                'severity': vuln.get('cvss', {}).get('score', 'N/A'),
                'published': vuln.get('published', 'N/A')
            })
        
        return vulnerabilities
    
    def _get_cvss_severity(self, metrics: Dict) -> str:
        """Extrait le score CVSS des métriques NVD"""
        cvss_v3 = metrics.get('cvssMetricV31', [])
        if cvss_v3:
            return str(cvss_v3[0].get('cvssData', {}).get('baseScore', 'N/A'))
        
        cvss_v2 = metrics.get('cvssMetricV2', [])
        if cvss_v2:
            return str(cvss_v2[0].get('cvssData', {}).get('baseScore', 'N/A'))
        
        return 'N/A'

class AdvancedWorkflowSecurityAnalyzer:
    def __init__(self):
        self.console = Console()
        self.vuln_db = MultiVulnDatabase()
        
        # Règles d'analyse étendues avec chemins spécifiques
        self.advanced_rules = {
            # === COMMANDES SYSTÈME DANGEREUSES ===
            'system_commands': {
                'patterns': [
                    r'\b(rm\s+-rf|sudo\s+rm|rmdir)\b',  # Suppression destructive
                    r'\b(chmod\s+777|chmod\s+-R\s+777)\b',  # Permissions dangereuses
                    r'\b(chown\s+root|sudo\s+chown)\b',  # Changement propriétaire
                    r'\b(systemctl|service)\s+(start|stop|restart)\b',  # Services système
                    r'\b(iptables|ufw|firewall-cmd)\b',  # Pare-feu
                    r'\b(crontab|at\s+now)\b',  # Tâches planifiées
                    r'\b(mount|umount)\b',  # Montage systèmes de fichiers
                    r'\b(fdisk|parted|mkfs)\b',  # Manipulation disques
                ],
                'severity': SeverityLevel.HIGH,
                'category': 'Commandes Système Dangereuses',
                'path': '/system/commands'
            },
            
            # === EXFILTRATION DE DONNÉES AVANCÉE ===
            'data_exfiltration_advanced': {
                'patterns': [
                    r'(tar|zip|gzip|7z|rar).*\|.*(curl|wget|nc)',  # Archive + transfert
                    r'(find|locate|grep).*-exec.*(curl|wget)',  # Recherche + exfiltration
                    r'(cat|head|tail).*\|.*(curl|wget|nc)',  # Lecture + transfert
                    r'(mysqldump|pg_dump|mongodump).*\|.*(curl|wget)',  # Export DB
                    r'(docker\s+save|docker\s+export).*\|.*(curl|wget)',  # Export conteneurs
                    r'(history|env|printenv).*\|.*(curl|wget)',  # Variables d'env
                    r'/proc/(version|cpuinfo|meminfo).*\|.*(curl|wget)',  # Info système
                    r'~\/\.(ssh|aws|config).*\|.*(curl|wget)',  # Fichiers config
                ],
                'severity': SeverityLevel.CRITICAL,
                'category': 'Exfiltration de Données Avancée',
                'path': '/security/exfiltration'
            },
            
            # === BACKDOORS ET PERSISTANCE ===
            'backdoors_persistence': {
                'patterns': [
                    r'echo.*>>\s*~\/\.(bashrc|profile|zshrc)',  # Modification shells
                    r'crontab.*-e.*echo',  # Backdoor cron
                    r'(useradd|adduser).*-p.*\$',  # Création utilisateurs
                    r'ssh-keygen.*-f.*\/\.ssh\/',  # Génération clés SSH
                    r'echo.*authorized_keys',  # Ajout clés SSH
                    r'(systemctl|service).*enable.*\w+\.service',  # Services persistants
                    r'\/etc\/rc\.local.*echo',  # Scripts démarrage
                    r'(ln|cp).*\/bin\/(sh|bash)',  # Création backdoors
                ],
                'severity': SeverityLevel.CRITICAL,
                'category': 'Backdoors et Persistance',
                'path': '/security/backdoors'
            },
            
            # === RECONNAISSANCE ET ÉNUMÉRATION ===
            'reconnaissance': {
                'patterns': [
                    r'\b(nmap|masscan|zmap)\b',  # Scan réseau
                    r'\b(nikto|dirb|gobuster|wfuzz)\b',  # Scan web
                    r'\b(enum4linux|smbclient|rpcclient)\b',  # Énumération SMB
                    r'\b(searchsploit|metasploit|msfconsole)\b',  # Outils exploit
                    r'\b(sqlmap|burpsuite|owasp-zap)\b',  # Test sécurité web
                    r'\b(wireshark|tcpdump|tshark)\b',  # Capture réseau
                    r'\/proc\/net\/(tcp|udp|arp)',  # Énumération réseau
                    r'netstat.*-[a-z]*[ln]',  # Énumération ports
                ],
                'severity': SeverityLevel.HIGH,
                'category': 'Reconnaissance et Énumération',
                'path': '/security/reconnaissance'
            },
            
            # === LATERAL MOVEMENT ===
            'lateral_movement': {
                'patterns': [
                    r'ssh.*-o.*StrictHostKeyChecking=no',  # SSH non sécurisé
                    r'scp.*-o.*StrictHostKeyChecking=no',  # SCP non sécurisé
                    r'rsync.*--rsh=ssh',  # Rsync via SSH
                    r'psexec|wmiexec|smbexec',  # Outils Windows
                    r'ssh.*-L\s+\d+:.*:\d+',  # Port forwarding
                    r'ssh.*-D\s+\d+',  # SOCKS proxy
                    r'proxychains|proxyresolv',  # Proxy chains
                    r'chisel|ngrok|localtunnel',  # Tunneling
                ],
                'severity': SeverityLevel.HIGH,
                'category': 'Mouvement Latéral',
                'path': '/security/lateral_movement'
            },
            
            # === SECRETS ET CREDENTIALS AVANCÉS ===
            'advanced_secrets': {
                'patterns': [
                    # Clés cloud
                    r'AKIA[0-9A-Z]{16}',  # AWS Access Key
                    r'[0-9a-zA-Z\/+]{40}',  # AWS Secret Key
                    r'AIza[0-9A-Za-z\-_]{35}',  # Google API Key
                    r'ya29\.[0-9A-Za-z\-_]+',  # Google OAuth
                    r'sk-[a-zA-Z0-9]{48}',  # OpenAI API Key
                    r'xoxb-[0-9]{11}-[0-9]{11}-[a-zA-Z0-9]{24}',  # Slack Bot Token
                    r'xoxp-[0-9]{11}-[0-9]{11}-[a-zA-Z0-9]{24}',  # Slack User Token
                    
                    # Tokens et certificats
                    r'-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----',
                    r'-----BEGIN CERTIFICATE-----',
                    r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*',  # JWT
                    
                    # Base de données
                    r'(mysql|postgresql|mongodb):\/\/[^:]+:[^@]+@',
                    r'redis:\/\/[^:]*:[^@]*@',
                    
                    # URLs sensibles
                    r'https?:\/\/[^\/]*:[^@]*@[^\/]+',  # URLs avec credentials
                ],
                'severity': SeverityLevel.CRITICAL,
                'category': 'Secrets et Credentials Avancés',
                'path': '/security/secrets'
            },
            
            # === CONTAINERS ET ORCHESTRATION ===
            'container_security': {
                'patterns': [
                    r'docker.*--privileged',
                    r'docker.*--cap-add=ALL',
                    r'docker.*--security-opt.*seccomp=unconfined',
                    r'docker.*--pid=host',
                    r'docker.*--net=host',
                    r'docker.*--ipc=host',
                    r'docker.*--uts=host',
                    r'docker.*-v\s+\/:/host',  # Mount host root
                    r'kubectl.*create.*secret',
                    r'kubectl.*apply.*-f.*http',  # Remote YAML
                    r'helm.*install.*--set.*password',
                    r'docker.*build.*--build-arg.*SECRET',
                ],
                'severity': SeverityLevel.HIGH,
                'category': 'Sécurité Conteneurs',
                'path': '/security/containers'
            },
            
            # === CI/CD PIPELINE ATTACKS ===
            'cicd_attacks': {
                'patterns': [
                    r'git.*clone.*http:\/\/',  # Clone non sécurisé
                    r'git.*config.*--global.*user\.',  # Config Git globale
                    r'git.*remote.*set-url.*http',  # Remote non sécurisé
                    r'npm.*publish.*--registry.*http',  # NPM non sécurisé
                    r'pip.*install.*--index-url.*http',  # PIP non sécurisé
                    r'gem.*push.*--host.*http',  # Ruby Gems non sécurisé
                    r'docker.*login.*--username.*--password',  # Docker login
                    r'aws.*configure.*set.*aws_access_key_id',  # AWS config
                    r'gcloud.*auth.*activate-service-account',  # GCP auth
                ],
                'severity': SeverityLevel.HIGH,
                'category': 'Attaques CI/CD',
                'path': '/security/cicd'
            },
            
            # === CRYPTO ET MINING ===
            'crypto_mining_advanced': {
                'patterns': [
                    # Mineurs populaires
                    r'\b(xmrig|cpuminer|ccminer|cgminer|bfgminer|t-rex)\b',
                    r'\b(phoenixminer|claymore|bminer|gminer)\b',
                    
                    # Pools de mining
                    r'stratum\+tcp:\/\/',
                    r'pool\.[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}:\d+',
                    r'(nanopool|ethermine|f2pool|antpool)\.org',
                    
                    # Cryptomonnaies
                    r'\b(monero|ethereum|bitcoin|litecoin|zcash).*pool\b',
                    r'wallet.*[13][a-km-zA-HJ-NP-Z1-9]{25,34}',  # Bitcoin addresses
                    r'0x[a-fA-F0-9]{40}',  # Ethereum addresses
                ],
                'severity': SeverityLevel.CRITICAL,
                'category': 'Cryptominage Avancé',
                'path': '/security/crypto_mining'
            },
            
            # === VULNÉRABILITÉS SPÉCIFIQUES ===
            'specific_vulnerabilities': {
                'patterns': [
                    # Log4Shell
                    r'\$\{jndi:(ldap|rmi|dns):\/\/',
                    
                    # Spring4Shell
                    r'class\.module\.classLoader',
                    
                    # Shellshock
                    r'\(\)\s*\{.*;\s*\}',
                    
                    # Command injection
                    r'[;&|`]\s*(cat|ls|id|whoami|uname)',
                    
                    # SQL Injection patterns
                    r"(union|select|insert|update|delete).*--",
                    r"(or|and)\s+1\s*=\s*1",
                    
                    # XSS patterns
                    r'<script[^>]*>.*<\/script>',
                    r'javascript:[^"\']*',
                    
                    # Path traversal
                    r'\.\.\/.*\.\.\/.*\.\.\/',
                    r'\.\.\\.*\.\.\\.*\.\.\\',
                ],
                'severity': SeverityLevel.CRITICAL,
                'category': 'Vulnérabilités Spécifiques',
                'path': '/security/specific_vulns'
            }
        }
        
        # Actions dangereuses étendues avec chemins
        self.dangerous_actions_extended = {
            'supply_chain_attacks': {
                'patterns': [
                    r'^(?!actions\/|github\/)[\w-]+\/[\w-]+@[^v]',  # Actions tierces sans tag version
                    r'@(main|master|HEAD|latest)$',  # Références non épinglées
                ],
                'list': [
                    'actions/checkout@main',
                    'actions/setup-node@master',
                    'peter-evans/create-pull-request@main',
                ],
                'severity': SeverityLevel.MEDIUM,
                'category': 'Attaques Supply Chain',
                'path': '/actions/supply_chain'
            },
            
            'deprecated_insecure_actions': {
                'list': [
                    'actions/checkout@v1',
                    'actions/setup-node@v1',
                    'actions/setup-python@v1',
                    'actions/cache@v1',
                    'actions/upload-artifact@v1',
                    'actions/download-artifact@v1',
                ],
                'severity': SeverityLevel.MEDIUM,
                'category': 'Actions Dépréciées/Insécures',
                'path': '/actions/deprecated'
            },
            
            'high_risk_actions': {
                'list': [
                    'google-github-actions/setup-gcloud',
                    'aws-actions/configure-aws-credentials',
                    'azure/login',
                    'docker/login-action',
                    'docker/build-push-action',
                ],
                'patterns': [
                    r'.*docker.*login.*',
                    r'.*aws.*credentials.*',
                    r'.*gcloud.*auth.*',
                ],
                'severity': SeverityLevel.HIGH,
                'category': 'Actions à Haut Risque',
                'path': '/actions/high_risk'
            }
        }
        
        # Domaines et URLs suspects étendus avec catégories
        self.suspicious_domains_extended = {
            'file_sharing': {
                'domains': [
                    'pastebin.com', 'hastebin.com', 'ghostbin.co', 'ix.io',
                    'paste.ee', 'controlc.com', 'justpaste.it', 'rentry.co',
                    'transfer.sh', 'file.io', 'wetransfer.com', 'sendspace.com',
                    'mega.nz', 'mediafire.com', 'rapidshare.com', 'uploaded.net'
                ],
                'severity': SeverityLevel.HIGH,
                'path': '/domains/file_sharing'
            },
            'url_shorteners': {
                'domains': [
                    'bit.ly', 'tinyurl.com', 'shorturl.at', 't.co', 'goo.gl',
                    'ow.ly', 'tiny.cc', 'is.gd', 'buff.ly', 'rebrand.ly'
                ],
                'severity': SeverityLevel.MEDIUM,
                'path': '/domains/url_shorteners'
            },
            'suspicious_tlds': {
                'tlds': ['.tk', '.ml', '.ga', '.cf', '.top', '.click', '.download'],
                'severity': SeverityLevel.MEDIUM,
                'path': '/domains/suspicious_tlds'
            },
            'crypto_related': {
                'domains': [
                    'coinhive.com', 'coin-hive.com', 'cnhv.co', 'authedmine.com',
                    'crypto-loot.com', 'webminepool.com', 'minero.cc'
                ],
                'severity': SeverityLevel.CRITICAL,
                'path': '/domains/crypto_mining'
            }
        }

    def load_workflow(self, path: str) -> Dict:
        """Charge le workflow YAML avec gestion d'erreurs"""
        try:
            with open(path, 'r', encoding='utf-8') as file:
                workflow_content = yaml.safe_load(file)
                self.console.print(f"[green]✅ Workflow chargé depuis: {path}[/green]")
                return workflow_content
        except FileNotFoundError:
            self.console.print(f"[red]❌ Fichier non trouvé: {path}[/red]")
            return {}
        except yaml.YAMLError as e:
            self.console.print(f"[red]❌ Erreur YAML dans {path}: {e}[/red]")
            return {}
        except Exception as e:
            self.console.print(f"[red]❌ Erreur lors du chargement de {path}: {e}[/red]")
            return {}

    def analyze_software_versions(self, command: str) -> List[SecurityAnomaly]:
        """Analyse les versions de logiciels pour détecter les vulnérabilités"""
        anomalies = []
        
        # Patterns pour détecter software + version
        software_patterns = {
            'node': r'node[js]?[@:\s]+v?(\d+\.\d+\.\d+)',
            'python': r'python[@:\s]+(\d+\.\d+\.\d+)',
            'java': r'java[@:\s]+(\d+\.\d+\.\d+)',
            'docker': r'docker[@:\s]+(\d+\.\d+\.\d+)',
            'nginx': r'nginx[@:\s]+(\d+\.\d+\.\d+)',
            'apache': r'apache[@:\s]+(\d+\.\d+\.\d+)',
            'mysql': r'mysql[@:\s]+(\d+\.\d+\.\d+)',
            'postgresql': r'postgres(?:ql)?[@:\s]+(\d+\.\d+\.\d+)',
            'redis': r'redis[@:\s]+(\d+\.\d+\.\d+)',
        }
        
        for software, pattern in software_patterns.items():
            matches = re.finditer(pattern, command, re.IGNORECASE)
            for match in matches:
                version = match.group(1)
                
                # Recherche des vulnérabilités pour ce logiciel/version
                try:
                    vulns = self.vuln_db.get_vulnerability_info(software, version)
                    if vulns:
                        cve_list = [v['id'] for v in vulns if v['id'] != 'N/A']
                        severity_scores = [float(v['severity']) for v in vulns 
                                         if v['severity'] != 'N/A' and str(v['severity']).replace('.', '').isdigit()]
                        
                        if severity_scores:
                            max_score = max(severity_scores)
                            severity = (SeverityLevel.CRITICAL if max_score >= 9.0 else
                                      SeverityLevel.HIGH if max_score >= 7.0 else
                                      SeverityLevel.MEDIUM if max_score >= 4.0 else
                                      SeverityLevel.LOW)
                        else:
                            severity = SeverityLevel.MEDIUM
                        
                        anomalies.append(SecurityAnomaly(
                            job="N/A",
                            step="N/A",
                            type=f"Vulnérabilités connues détectées",
                            detail=f"{software} {version} - {len(vulns)} vulnérabilité(s) trouvée(s)",
                            severity=severity,
                            category='Versions Vulnérables',
                            recommendation=f"Mettre à jour {software} vers une version plus récente",
                            cve_matches=cve_list,
                            references=[f"/vulnerabilities/{software}/{version}"]
                        ))
                except Exception as e:
                    self.console.print(f"[yellow]Erreur analyse vulnérabilités {software}: {e}[/yellow]")
        
        return anomalies

    def analyze_network_connections(self, command: str) -> List[SecurityAnomaly]:
        """Analyse les connexions réseau suspectes"""
        anomalies = []
        
        # Extraction des IPs et domaines
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        domain_pattern = r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b'
        
        ips = re.findall(ip_pattern, command)
        domains = re.findall(domain_pattern, command)
        
        # Vérification des IPs privées/publiques
        for ip in set(ips):
            if self._is_public_ip(ip):
                anomalies.append(SecurityAnomaly(
                    job="N/A",
                    step="N/A",
                    type="Connexion IP publique",
                    detail=f"Connexion vers IP publique: {ip}",
                    severity=SeverityLevel.MEDIUM,
                    category='Connexions Réseau',
                    recommendation="Vérifier la légitimité de cette connexion",
                    references=[f"/network/connections/ip/{ip}"]
                ))
        
        # Vérification des domaines suspects
        for domain in set(domains):
            for category, info in self.suspicious_domains_extended.items():
                if 'domains' in info and domain.lower() in [d.lower() for d in info['domains']]:
                    anomalies.append(SecurityAnomaly(
                        job="N/A",
                        step="N/A",
                        type=f"Domaine suspect ({category})",
                        detail=f"Connexion vers domaine suspect: {domain}",
                        severity=info['severity'],
                        category='Domaines Suspects',
                        recommendation=f"Éviter les connexions vers {category}",
                        references=[info['path']]
                    ))
                elif 'tlds' in info:
                    for tld in info['tlds']:
                        if domain.lower().endswith(tld):
                            anomalies.append(SecurityAnomaly(
                                job="N/A",
                                step="N/A",
                                type=f"TLD suspect ({tld})",
                                detail=f"Domaine avec TLD suspect: {domain}",
                                severity=info['severity'],
                                category='TLD Suspects',
                                recommendation="Vérifier la légitimité de ce domaine",
                                references=[info['path']]
                            ))
        
        return anomalies

    def _is_public_ip(self, ip: str) -> bool:
        """Vérifie si une IP est publique (non privée)"""
        import ipaddress
        try:
            ip_obj = ipaddress.ip_address(ip)
            return not ip_obj.is_private and not ip_obj.is_loopback and not ip_obj.is_multicast
        except:
            return False

    def analyze_file_operations(self, command: str) -> List[SecurityAnomaly]:
        """Analyse les opérations sur fichiers sensibles"""
        anomalies = []
        
        sensitive_paths = {
            '/etc/passwd': 'Fichier des utilisateurs système',
            '/etc/shadow': 'Fichier des mots de passe',
            '/etc/sudoers': 'Configuration sudo',
            '/etc/hosts': 'Résolution DNS',
            '/etc/crontab': 'Tâches planifiées',
            '/root/.ssh/': 'Clés SSH root',
            '/home/*/.ssh/': 'Clés SSH utilisateurs',
            '~/.aws/': 'Configuration AWS',
            '~/.docker/': 'Configuration Docker',
            '/proc/': 'Système de fichiers proc',
            '/sys/': 'Système de fichiers sys',
            '/dev/': 'Périphériques système'
        }
        
        for path, description in sensitive_paths.items():
            if path in command:
                anomalies.append(SecurityAnomaly(
                    job="N/A",
                    step="N/A",
                    type="Accès fichier sensible",
                    detail=f"Accès à {path} ({description})",
                    severity=SeverityLevel.HIGH,
                    category='Fichiers Sensibles',
                    recommendation=f"Vérifier la nécessité d'accéder à {path}",
                    references=[f"/filesystem/sensitive{path}"]
                ))
        
        return anomalies

    def detect_anomalies(self, workflow: Dict) -> List[SecurityAnomaly]:
        """Détection principale des anomalies avec toutes les règles avancées"""
        if not workflow:
            return []
        
        anomal
