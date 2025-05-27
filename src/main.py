# Imports existants
from report_generator import export_to_pdf, export_to_csv, AdvancedReportGenerator
from threat_intel.vulners import MultiVulnDatabase
import yaml
import re
import json
import hashlib
import base64
from urllib.parse import urlparse
from typing import Dict, List, Set, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
from rich import print
from rich.table import Table
from rich.panel import Panel
from rich.console import Console
from rich.progress import track
import sys
import argparse
from datetime import datetime
import os


import time
import argparse
# ... autres imports ...

# AJOUTE LA FONCTION ICI, AVANT LES CLASSES
def show_startup_banner():
    """Banner stylé au démarrage"""
    banner = """
╔══════════════════════════════════════════════════════════════════╗
║  ░██████╗░██╗░░██╗░█████╗░░██████╗████████╗                      ║
║  ██╔════╝░██║░░██║██╔══██╗██╔════╝╚══██╔══╝                      ║
║  ██║░░██╗░███████║██║░░██║╚█████╗░░░░██║░░░                      ║
║  ██║░░╚██╗██╔══██║██║░░██║░╚═══██╗░░░██║░░░                      ║
║  ╚██████╔╝██║░░██║╚█████╔╝██████╔╝░░░██║░░░                      ║
║  ░╚═════╝░╚═╝░░╚═╝░╚════╝░╚═════╝░░░░╚═╝░░░                      ║
║                                                                  ║
║  ██████╗░███████╗██████╗░██╗░░░░░░█████╗░██╗░░░██╗               ║
║  ██╔══██╗██╔════╝██╔══██╗██║░░░░░██╔══██╗╚██╗░██╔╝               ║
║  ██║░░██║█████╗░░██████╔╝██║░░░░░██║░░██║░╚████╔╝░               ║
║  ██║░░██║██╔══╝░░██╔═══╝░██║░░░░░██║░░██║░░╚██╔╝░░               ║
║  ██████╔╝███████╗██║░░░░░███████╗╚█████╔╝░░░██║░░░               ║
║  ╚═════╝░╚══════╝╚═╝░░░░░╚══════╝░╚════╝░░░░╚═╝░░░               ║
║                                                                  ║
║                👻 DevSecOps Security Analyzer 👻                 ║
║              https://github.com/ahmed/GhostDeploy               ║
╚══════════════════════════════════════════════════════════════════╝
    """
    
    print(f"\n{banner}")
    print("🚀 Initialisation de GhostDeploy...")
    time.sleep(1)
    print("="*80 + "\n")

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

class AdvancedWorkflowSecurityAnalyzer:
    def __init__(self):
        self.console = Console()
        self.vuln_db = MultiVulnDatabase()
        
        # Règles de sécurité avancées
        self.security_rules = {
            # === COMMANDES SYSTÈME DANGEREUSES ===
            'dangerous_commands': {
                'patterns': [
                    r'\b(rm\s+-rf|sudo\s+rm|rmdir)\b',
                    r'\b(chmod\s+777|chmod\s+-R\s+777)\b',
                    r'\b(chown\s+root|sudo\s+chown)\b',
                    r'\b(systemctl|service)\s+(start|stop|restart)\b',
                    r'\b(mount|umount)\b',
                    r'\b(fdisk|parted|mkfs)\b'
                ],
                'severity': SeverityLevel.HIGH,
                'category': 'Commandes Système Dangereuses'
            },
            
            # === OUTILS RÉSEAU SUSPECTS ===
            'network_tools': {
                'patterns': [
                    r'\b(curl|wget)\s+.*\|\s*(sh|bash)\b',
                    r'\b(nc|netcat|telnet)\b',
                    r'\b(nmap|masscan|zmap)\b',
                    r'\b(nikto|dirb|gobuster)\b'
                ],
                'severity': SeverityLevel.HIGH,
                'category': 'Outils Réseau Suspects'
            },
            
            # === EXFILTRATION DE DONNÉES ===
            'data_exfiltration': {
                'patterns': [
                    r'(tar|zip|gzip|7z).*\|.*(curl|wget)',
                    r'(cat|head|tail|grep).*\|.*(curl|wget)',
                    r'(env|printenv|history).*\|.*(curl|wget)',
                    r'(find|locate).*-exec.*(curl|wget)',
                    r'\/proc\/(version|cpuinfo|meminfo).*\|.*(curl|wget)'
                ],
                'severity': SeverityLevel.CRITICAL,
                'category': 'Exfiltration de Données'
            },
            
            # === BACKDOORS ET PERSISTANCE ===
            'backdoors': {
                'patterns': [
                    r'echo.*>>\s*~\/\.(bashrc|profile|bash_profile)',
                    r'crontab.*-e',
                    r'(useradd|adduser).*-p',
                    r'ssh-keygen.*-f.*\/\.ssh\/',
                    r'echo.*authorized_keys',
                    r'\/etc\/rc\.local.*echo'
                ],
                'severity': SeverityLevel.CRITICAL,
                'category': 'Backdoors et Persistance'
            },
            
            # === SECRETS ET CREDENTIALS ===
            'secrets': {
                'patterns': [
                    r'AKIA[0-9A-Z]{16}',  # AWS Access Key
                    r'[0-9a-zA-Z\/+]{40}',  # AWS Secret Key (générique)
                    r'AIza[0-9A-Za-z\-_]{35}',  # Google API Key
                    r'sk-[a-zA-Z0-9]{48}',  # OpenAI API Key
                    r'xoxb-[0-9]{11}-[0-9]{11}-[a-zA-Z0-9]{24}',  # Slack Bot Token
                    r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*',  # JWT
                    r'-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----',
                    r'(password|passwd|pwd|token|key)\s*[:=]\s*["\'][^"\']{8,}["\']'
                ],
                'severity': SeverityLevel.CRITICAL,
                'category': 'Secrets et Credentials'
            },
            
            # === CRYPTOMINAGE ===
            'crypto_mining': {
                'patterns': [
                    r'\b(xmrig|cpuminer|ccminer|cgminer|bfgminer)\b',
                    r'\b(phoenixminer|claymore|bminer)\b',
                    r'stratum\+tcp://',
                    r'pool\.[a-zA-Z0-9.-]+:[0-9]+',
                    r'\b(monero|bitcoin|ethereum|litecoin).*pool\b',
                    r'0x[a-fA-F0-9]{40}',  # Ethereum address
                    r'[13][a-km-zA-HJ-NP-Z1-9]{25,34}'  # Bitcoin address
                ],
                'severity': SeverityLevel.CRITICAL,
                'category': 'Cryptominage'
            },
            
            # === RECONNAISSANCE ===
            'reconnaissance': {
                'patterns': [
                    r'\b(enum4linux|smbclient|rpcclient)\b',
                    r'\b(searchsploit|metasploit|msfconsole)\b',
                    r'\b(sqlmap|burpsuite|owasp-zap)\b',
                    r'\b(wireshark|tcpdump|tshark)\b',
                    r'netstat.*-[a-z]*[ln]',
                    r'ps\s+aux.*grep'
                ],
                'severity': SeverityLevel.MEDIUM,
                'category': 'Reconnaissance'
            }
        }
        
        # Domaines suspects
        self.suspicious_domains = [
            'pastebin.com', 'hastebin.com', 'ghostbin.co', 'ix.io',
            'transfer.sh', 'file.io', 'wetransfer.com',
            'bit.ly', 'tinyurl.com', 'short.link',
            'coinhive.com', 'coin-hive.com', 'crypto-loot.com'
        ]
        
        # URLs suspectes
        self.suspicious_url_patterns = [
            r'http://[^/\s]+',  # HTTP non sécurisé
            r'https://[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}',  # IP directe
            r'(ftp|sftp)://[^/\s]+',  # Protocoles de transfert
        ]

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

    def analyze_software_versions(self, command: str, job_name: str, step_name: str) -> List[SecurityAnomaly]:
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
            'redis': r'redis[@:\s]+(\d+\.\d+\.\d+)'
        }
        
        for software, pattern in software_patterns.items():
            matches = re.finditer(pattern, command, re.IGNORECASE)
            for match in matches:
                version = match.group(1)
                
                try:
                    # Utilise ta classe MultiVulnDatabase
                    vulns = self.vuln_db.get_vulnerability_info(software, version)
                    if vulns:
                        cve_list = [v.get('id', 'N/A') for v in vulns if v.get('id') != 'N/A']
                        
                        anomalies.append(SecurityAnomaly(
                            job=job_name,
                            step=step_name,
                            type=f"Vulnérabilités détectées",
                            detail=f"{software} {version} - {len(vulns)} vulnérabilité(s) connue(s)",
                            severity=SeverityLevel.HIGH,
                            category='Versions Vulnérables',
                            recommendation=f"Mettre à jour {software} vers une version plus récente",
                            cve_matches=cve_list,
                            references=[f"/vulnerabilities/{software}/{version}"]
                        ))
                except Exception as e:
                    self.console.print(f"[yellow]⚠️ Erreur analyse vulnérabilités {software}: {e}[/yellow]")
        
        return anomalies

    def check_suspicious_urls(self, command: str, job_name: str, step_name: str) -> List[SecurityAnomaly]:
        """Vérifie les URLs suspectes dans les commandes"""
        anomalies = []
        
        # Extraction d'URLs
        url_pattern = r'https?://[^\s)"\';]+'
        urls = re.findall(url_pattern, command)
        
        for url in urls:
            parsed_url = urlparse(url)
            domain = parsed_url.netloc.lower()
            
            # Vérification domaines suspects
            for suspicious_domain in self.suspicious_domains:
                if suspicious_domain in domain:
                    anomalies.append(SecurityAnomaly(
                        job=job_name,
                        step=step_name,
                        type="Domaine suspect",
                        detail=f"Domaine suspect détecté: {domain}",
                        severity=SeverityLevel.HIGH,
                        category='Domaines Suspects',
                        recommendation=f"Vérifier la légitimité de {domain}"
                    ))
            
            # Vérification patterns d'URL suspects
            for pattern in self.suspicious_url_patterns:
                if re.match(pattern, url):
                    severity = SeverityLevel.MEDIUM
                    if pattern.startswith('http://'):
                        severity = SeverityLevel.HIGH
                    
                    anomalies.append(SecurityAnomaly(
                        job=job_name,
                        step=step_name,
                        type="URL suspecte",
                        detail=f"Protocole HTTP non sécurisé: {url[:50]}..." if len(url) > 50 else f"URL suspecte: {url}",
                        severity=severity,
                        category='URLs Suspectes',
                        recommendation="Vérifier la légitimité de l'URL"
                    ))
        
        return anomalies

    def detect_anomalies(self, workflow: Dict) -> List[SecurityAnomaly]:
        """Détection principale des anomalies avec toutes les règles avancées"""
        if not workflow:
            return []
        
        anomalies = []
        jobs = workflow.get('jobs', {})
        
        for job_name, job_details in track(jobs.items(), description="Analyse des jobs..."):
            steps = job_details.get('steps', [])
            
            for step_idx, step in enumerate(steps):
                step_name = step.get('name', f'Step {step_idx + 1}')
                
                # Analyse des commandes shell
                if 'run' in step:
                    command = step['run']
                    
                    # Analyse avec les règles de sécurité
                    for rule_name, rule_info in self.security_rules.items():
                        for pattern in rule_info['patterns']:
                            if re.search(pattern, command, re.IGNORECASE | re.MULTILINE):
                                anomalies.append(SecurityAnomaly(
                                    job=job_name,
                                    step=step_name,
                                    type="Commande suspecte détectée",
                                    detail=f"Pattern {rule_name} trouvé dans la commande",
                                    severity=rule_info['severity'],
                                    category=rule_info['category'],
                                    recommendation=self._get_recommendation(rule_name),
                                    cwe_id=self._get_cwe_id(rule_name)
                                ))
                    
                    # Analyse des versions de logiciels
                    version_anomalies = self.analyze_software_versions(command, job_name, step_name)
                    anomalies.extend(version_anomalies)
                    
                    # Analyse des URLs suspectes
                    url_anomalies = self.check_suspicious_urls(command, job_name, step_name)
                    anomalies.extend(url_anomalies)
                
                # Analyse des actions utilisées
                if 'uses' in step:
                    action = step['uses']
                    
                    # Actions tierces non vérifiées
                    if not action.startswith(('actions/', 'github/')):
                        anomalies.append(SecurityAnomaly(
                            job=job_name,
                            step=step_name,
                            type="Action tierce",
                            detail=f"Action tierce utilisée: {action}",
                            severity=SeverityLevel.MEDIUM,
                            category='Actions Tierces',
                            recommendation="Vérifier la réputation et épingler la version"
                        ))
                    
                    # Versions non épinglées
                    if action.endswith(('@main', '@master', '@latest')):
                        anomalies.append(SecurityAnomaly(
                            job=job_name,
                            step=step_name,
                            type="Version non épinglée",
                            detail=f"Action avec version flottante: {action}",
                            severity=SeverityLevel.MEDIUM,
                            category='Gestion des Versions',
                            recommendation="Épingler à une version ou un hash spécifique"
                        ))
        
        return anomalies

    def _get_recommendation(self, rule_name: str) -> str:
        """Retourne une recommandation basée sur la règle"""
        recommendations = {
            'dangerous_commands': "Éviter les commandes système dangereuses, utiliser des alternatives sécurisées",
            'network_tools': "Éviter les outils réseau non essentiels, utiliser des alternatives sécurisées",
            'data_exfiltration': "CRITIQUE: Examiner ces commandes, possibles tentatives d'exfiltration de données",
            'backdoors': "CRITIQUE: Commandes de backdoor détectées, à supprimer immédiatement",
            'secrets': "Utiliser GitHub Secrets pour stocker les informations sensibles",
            'crypto_mining': "CRITIQUE: Activité de cryptominage détectée, à supprimer immédiatement",
            'reconnaissance': "Limiter l'utilisation d'outils de reconnaissance à des fins légitimes"
        }
        return recommendations.get(rule_name, "Examiner cette anomalie de sécurité")

    def _get_cwe_id(self, rule_name: str) -> str:
        """Retourne l'ID CWE correspondant à la règle"""
        cwe_mapping = {
            'dangerous_commands': "CWE-78",
            'network_tools': "CWE-200",
            'data_exfiltration': "CWE-200",
            'backdoors': "CWE-506",
            'secrets': "CWE-798",
            'crypto_mining': "CWE-506",
            'reconnaissance': "CWE-200"
        }
        return cwe_mapping.get(rule_name, "CWE-noinfo")

    def generate_security_score(self, anomalies: List[SecurityAnomaly]) -> Tuple[int, str]:
        """Génère un score de sécurité basé sur les anomalies"""
        if not anomalies:
            return 100, "EXCELLENT"
        
        score = 100
        severity_weights = {
            SeverityLevel.CRITICAL: 25,
            SeverityLevel.HIGH: 15,
            SeverityLevel.MEDIUM: 8,
            SeverityLevel.LOW: 3,
            SeverityLevel.INFO: 1
        }
        
        for anomaly in anomalies:
            score -= severity_weights.get(anomaly.severity, 5)
        
        score = max(0, score)
        
        if score >= 90:
            grade = "EXCELLENT"
        elif score >= 75:
            grade = "BON"
        elif score >= 50:
            grade = "MOYEN"
        elif score >= 25:
            grade = "FAIBLE"
        else:
            grade = "CRITIQUE"
        
        return score, grade

    def print_security_report(self, anomalies: List[SecurityAnomaly], workflow_path: str):
        """Affiche un rapport de sécurité complet avec Rich"""
        score, grade = self.generate_security_score(anomalies)
        
        # En-tête du rapport
        self.console.print(Panel.fit(
            f"[bold blue]🔐 RAPPORT DE SÉCURITÉ DEVSECOPS[/bold blue]\n"
            f"[white]Fichier analysé: {workflow_path}[/white]\n"
            f"[white]Score de sécurité: {score}/100 ({grade})[/white]\n"
            f"[white]Anomalies détectées: {len(anomalies)}[/white]",
            border_style="blue"
        ))
        
        if not anomalies:
            self.console.print(Panel("✅ [green]Aucune anomalie de sécurité détectée![/green]", border_style="green"))
            return
        
        # Statistiques par sévérité
        severity_counts = {}
        for anomaly in anomalies:
            severity = anomaly.severity.name
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        if severity_counts:
            severity_table = Table(title="Répartition par Sévérité", show_header=True)
            severity_table.add_column("Sévérité", style="bold")
            severity_table.add_column("Nombre", style="bold cyan")
            
            for severity, count in severity_counts.items():
                if severity == 'CRITICAL':
                    severity_table.add_row(f"🔴 {severity}", str(count))
                elif severity == 'HIGH':
                    severity_table.add_row(f"🟠 {severity}", str(count))
                elif severity == 'MEDIUM':
                    severity_table.add_row(f"🟡 {severity}", str(count))
                else:
                    severity_table.add_row(f"🟢 {severity}", str(count))
            
            self.console.print(severity_table)
        
        # Tableau détaillé des anomalies
        anomalies_table = Table(title="Détail des Anomalies", show_header=True, header_style="bold red")
        anomalies_table.add_column("Sévérité", style="bold", no_wrap=True)
        anomalies_table.add_column("Job", style="cyan", no_wrap=True)
        anomalies_table.add_column("Step", style="green")
        anomalies_table.add_column("Type", style="yellow")
        anomalies_table.add_column("Détail", style="white")
        anomalies_table.add_column("Recommandation", style="blue")
        
        # Trier par sévérité (critique en premier)
        severity_order = {
            SeverityLevel.CRITICAL: 0,
            SeverityLevel.HIGH: 1,
            SeverityLevel.MEDIUM: 2,
            SeverityLevel.LOW: 3,
            SeverityLevel.INFO: 4
        }
        
        sorted_anomalies = sorted(anomalies, key=lambda x: severity_order[x.severity])
        
        for anomaly in sorted_anomalies:
            anomalies_table.add_row(
                anomaly.severity.value,
                anomaly.job,
                anomaly.step,
                anomaly.type,
                anomaly.detail,
                anomaly.recommendation
            )
        
        self.console.print(anomalies_table)
        
        # Recommandations urgentes
        critical_count = len([a for a in anomalies if a.severity == SeverityLevel.CRITICAL])
        high_count = len([a for a in anomalies if a.severity == SeverityLevel.HIGH])
        
        if critical_count > 0 or high_count > 0:
            recommendations = Panel(
                f"[bold red]⚠️ ACTIONS URGENTES REQUISES[/bold red]\n\n"
                f"• Corriger immédiatement les anomalies critiques et élevées\n"
                f"• Réviser les permissions accordées aux workflows\n"
                f"• Implémenter une politique de sécurité DevSecOps\n"
                f"• Effectuer un audit de sécurité complet",
                title="Recommandations Urgentes",
                border_style="red"
            )
            self.console.print(recommendations)

def main():
    """Fonction principale"""

    show_startup_banner()

    parser = argparse.ArgumentParser(description='Analyseur de Sécurité DevSecOps')
    parser.add_argument('workflow', help='Chemin vers le fichier workflow YAML')
    parser.add_argument('--csv', help='Exporter en CSV (chemin du fichier)')
    parser.add_argument('--pdf', help='Exporter en PDF (chemin du fichier)')
    parser.add_argument('--excel', help='Exporter en Excel (chemin du fichier)')
    parser.add_argument('--html', help='Exporter en dashboard HTML (chemin du fichier)')
    parser.add_argument('--all-formats', action='store_true', help='Exporter dans tous les formats')
    parser.add_argument('--auto-export', action='store_true', help='Export automatique avec timestamp')
    
    args = parser.parse_args()
    
    # Initialiser l'analyseur
    analyzer = AdvancedWorkflowSecurityAnalyzer()
    report_generator = AdvancedReportGenerator()
    
    print("🔍 Chargement et analyse du workflow...")
    workflow = analyzer.load_workflow(args.workflow)
    
    if not workflow:
        print("❌ Impossible de charger le workflow")
        sys.exit(1)
    
    print("🔐 Analyse de sécurité en cours...")
    anomalies = analyzer.detect_anomalies(workflow)
    
    # Générer le score et le résumé
    score, grade = analyzer.generate_security_score(anomalies)
    summary = report_generator.generate_executive_summary(anomalies, args.workflow, score, grade)
    
    print("📊 Génération du rapport...")
    analyzer.print_security_report(anomalies, args.workflow)
    
    # Préparation pour les exports
    base_name = os.path.splitext(args.workflow)[0]
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # === CHOIX UTILISATEUR POUR GÉNÉRATION DES RAPPORTS ===
    generate_reports = False
    
    # Si aucune option d'export spécifiée, demander à l'utilisateur
    if not any([args.csv, args.pdf, args.excel, args.html, args.auto_export, args.all_formats]):
        print(f"\n📄 Voulez-vous générer des rapports de sécurité ?")
        print(f"   1️⃣  Oui - Générer CSV, PDF et HTML dans le répertoire courant")
        print(f"   2️⃣  Non - Terminer l'analyse (affichage console seulement)")
        
        try:
            choice = input("\n👆 Votre choix (1 ou 2) : ").strip()
            
            if choice == "1":
                generate_reports = True
                print("✅ Génération des rapports activée")
            elif choice == "2":
                generate_reports = False
                print("✅ Analyse terminée sans génération de fichiers")
            else:
                print("⚠️  Choix invalide, pas de génération de rapports")
                generate_reports = False
                
        except KeyboardInterrupt:
            print("\n\n❌ Analyse interrompue par l'utilisateur")
            sys.exit(0)
        except Exception:
            print("⚠️  Erreur de saisie, pas de génération de rapports")
            generate_reports = False
    else:
        # Si des options d'export sont spécifiées, les honorer
        generate_reports = True
    
    # Génération des rapports si demandée
    if generate_reports:
        print("\n📄 Génération des rapports en cours...")
        
        # Exports spécifiques d'abord (si demandés)
        if args.csv:
            if report_generator.export_to_csv_advanced(anomalies, args.csv, summary):
                print(f"✅ Rapport CSV exporté: {args.csv}")
        
        if args.pdf:
            if report_generator.export_to_pdf_advanced(anomalies, args.pdf, summary):
                print(f"✅ Rapport PDF exporté: {args.pdf}")
        
        if args.excel:
            if report_generator.export_to_excel_advanced(anomalies, args.excel, summary):
                print(f"✅ Rapport Excel exporté: {args.excel}")
        
        if args.html:
            if report_generator.export_to_html_dashboard(anomalies, args.html, summary):
                print(f"✅ Dashboard HTML exporté: {args.html}")
        
        # Export automatique (si pas d'options spécifiques ou si --auto-export/--all-formats)
        if (not any([args.csv, args.pdf, args.excel, args.html]) and generate_reports) or args.auto_export or args.all_formats:
            # CSV
            csv_path = f"{base_name}_security_report_{timestamp}.csv"
            if report_generator.export_to_csv_advanced(anomalies, csv_path, summary):
                print(f"✅ Rapport CSV: {csv_path}")
            
            # PDF
            pdf_path = f"{base_name}_security_report_{timestamp}.pdf"
            if report_generator.export_to_pdf_advanced(anomalies, pdf_path, summary):
                print(f"✅ Rapport PDF: {pdf_path}")
            
            # HTML Dashboard
            html_path = f"{base_name}_security_dashboard_{timestamp}.html"
            if report_generator.export_to_html_dashboard(anomalies, html_path, summary):
                print(f"✅ Dashboard HTML: {html_path}")
        
        print(f"📁 Rapports générés dans le répertoire courant")
    
    # Résumé final
    print(f"\n🎯 Analyse terminée:")
    print(f"   📁 Fichier: {args.workflow}")
    print(f"   🔢 Score: {score}/100 ({grade})")
    print(f"   ⚠️  Anomalies: {len(anomalies)}")
    
    if generate_reports:
        print(f"   📄 Rapports générés avec succès")
    else:
        print(f"   👀 Consultation console uniquement")
    
    # Code de sortie basé sur la sévérité
    critical_count = sum(1 for a in anomalies if a.severity == SeverityLevel.CRITICAL)
    high_count = sum(1 for a in anomalies if a.severity == SeverityLevel.HIGH)
    
    if critical_count > 0:
        sys.exit(2)  # Anomalies critiques
    elif high_count > 0:
        sys.exit(1)  # Anomalies élevées
    else:
        sys.exit(0)  # Tout va bien

if __name__ == "__main__":
    main()
