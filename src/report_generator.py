import csv
import json
import os
from datetime import datetime
from typing import List, Dict, Optional
from dataclasses import asdict
import base64
from io import BytesIO

# Imports pour PDF avancé
from reportlab.lib.pagesizes import letter, A4
from reportlab.pdfgen import canvas
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, 
    PageBreak, KeepTogether
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY
from reportlab.graphics.shapes import Drawing
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics import renderPDF

# Imports pour Excel avancé
try:
    import xlsxwriter
    EXCEL_AVAILABLE = True
except ImportError:
    EXCEL_AVAILABLE = False

class AdvancedReportGenerator:
    """Générateur de rapports avancés pour l'analyseur DevSecOps"""
    
    def __init__(self):
        self.report_timestamp = datetime.now()
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()
    
    def _setup_custom_styles(self):
        """Configuration des styles personnalisés pour les rapports"""
        # Style titre principal
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            alignment=TA_CENTER,
            textColor=colors.darkblue,
            fontName='Helvetica-Bold'
        ))
        
        # Style sous-titre
        self.styles.add(ParagraphStyle(
            name='CustomSubTitle',
            parent=self.styles['Heading2'],
            fontSize=16,
            spaceAfter=20,
            alignment=TA_LEFT,
            textColor=colors.darkred,
            fontName='Helvetica-Bold'
        ))
        
        # Style pour les résumés exécutifs
        self.styles.add(ParagraphStyle(
            name='ExecutiveSummary',
            parent=self.styles['Normal'],
            fontSize=12,
            spaceAfter=15,
            alignment=TA_JUSTIFY,
            leftIndent=20,
            rightIndent=20,
            textColor=colors.black,
            backColor=colors.lightgrey,
            borderPadding=10
        ))

    def generate_executive_summary(self, anomalies: List, workflow_path: str, 
                                 security_score: int, grade: str) -> Dict:
        """Génère un résumé exécutif détaillé"""
        total_anomalies = len(anomalies)
        
        # Comptage par sévérité
        severity_counts = {}
        for anomaly in anomalies:
            severity = anomaly.severity.name
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        # Comptage par catégorie
        category_counts = {}
        for anomaly in anomalies:
            category = anomaly.category
            category_counts[category] = category_counts.get(category, 0) + 1
        
        # Top 5 des catégories les plus problématiques
        top_categories = sorted(category_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        
        # Calcul du risque global
        risk_level = "FAIBLE"
        if severity_counts.get('CRITICAL', 0) > 0:
            risk_level = "CRITIQUE"
        elif severity_counts.get('HIGH', 0) > 3:
            risk_level = "ÉLEVÉ"
        elif severity_counts.get('MEDIUM', 0) > 5:
            risk_level = "MOYEN"
        
        return {
            'workflow_path': workflow_path,
            'analysis_date': self.report_timestamp.strftime("%d/%m/%Y à %H:%M:%S"),
            'security_score': security_score,
            'grade': grade,
            'risk_level': risk_level,
            'total_anomalies': total_anomalies,
            'severity_breakdown': severity_counts,
            'category_breakdown': category_counts,
            'top_categories': top_categories,
            'critical_issues': severity_counts.get('CRITICAL', 0),
            'high_issues': severity_counts.get('HIGH', 0),
            'recommendations_count': len([a for a in anomalies if a.recommendation])
        }

    def export_to_csv(self, anomalies: List, filepath: str) -> bool:
        """Export CSV basique (compatibilité)"""
        try:
            with open(filepath, mode='w', newline='', encoding='utf-8') as file:
                writer = csv.writer(file)
                # En-têtes
                writer.writerow(["Sévérité", "Job", "Step", "Type", "Détail", "Recommandation"])
                # Données
                for a in anomalies:
                    writer.writerow([a.severity.value, a.job, a.step, a.type, a.detail, a.recommendation])
            return True
        except Exception as e:
            print(f"Erreur lors de l'export CSV: {e}")
            return False

    def export_to_csv_advanced(self, anomalies: List, filepath: str, 
                              summary: Dict = None) -> bool:
        """Export CSV avancé avec métadonnées et statistiques"""
        try:
            with open(filepath, mode='w', newline='', encoding='utf-8') as file:
                writer = csv.writer(file)
                
                # Métadonnées du rapport
                if summary:
                    writer.writerow(["=== RÉSUMÉ EXÉCUTIF ==="])
                    writer.writerow(["Fichier analysé", summary['workflow_path']])
                    writer.writerow(["Date d'analyse", summary['analysis_date']])
                    writer.writerow(["Score de sécurité", f"{summary['security_score']}/100 ({summary['grade']})"])
                    writer.writerow(["Niveau de risque", summary['risk_level']])
                    writer.writerow(["Total anomalies", summary['total_anomalies']])
                    writer.writerow([])
                    
                    # Répartition par sévérité
                    writer.writerow(["=== RÉPARTITION PAR SÉVÉRITÉ ==="])
                    for severity, count in summary['severity_breakdown'].items():
                        writer.writerow([severity, count])
                    writer.writerow([])
                    
                    # Top catégories
                    writer.writerow(["=== TOP 5 CATÉGORIES PROBLÉMATIQUES ==="])
                    for category, count in summary['top_categories']:
                        writer.writerow([category, count])
                    writer.writerow([])
                
                # En-têtes détaillés
                writer.writerow(["=== DÉTAIL DES ANOMALIES ==="])
                writer.writerow([
                    "ID", "Sévérité", "Job", "Step", "Type", "Catégorie", 
                    "Détail", "Recommandation", "CWE", "CVE", "Références"
                ])
                
                # Données des anomalies
                for i, anomaly in enumerate(anomalies, 1):
                    writer.writerow([
                        i,
                        anomaly.severity.value,
                        anomaly.job,
                        anomaly.step,
                        anomaly.type,
                        anomaly.category,
                        anomaly.detail,
                        anomaly.recommendation,
                        getattr(anomaly, 'cwe_id', None) or "N/A",
                        ", ".join(getattr(anomaly, 'cve_matches', []) or []) or "N/A",
                        ", ".join(getattr(anomaly, 'references', []) or []) or "N/A"
                    ])
            
            return True
        except Exception as e:
            print(f"Erreur lors de l'export CSV avancé: {e}")
            return False

    def export_to_pdf(self, anomalies: List, filepath: str) -> bool:
        """Export PDF basique (compatibilité)"""
        try:
            c = canvas.Canvas(filepath, pagesize=letter)
            width, height = letter
            c.setFont("Helvetica-Bold", 16)
            c.drawString(30, height - 40, "Rapport de sécurité DevSecOps")
            c.setFont("Helvetica", 12)
            y = height - 70
            
            data = [["Sévérité", "Job", "Step", "Type", "Détail", "Recommandation"]]
            for a in anomalies:
                data.append([a.severity.value, a.job, a.step, a.type, a.detail, a.recommendation])
            
            table = Table(data, colWidths=[70, 50, 80, 80, 130, 130])
            style = TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.gray),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ])
            table.setStyle(style)
            
            # Positionner la table sur la page
            table.wrapOn(c, width, height)
            table.drawOn(c, 30, y - len(data)*18)
            c.save()
            return True
        except Exception as e:
            print(f"Erreur lors de l'export PDF: {e}")
            return False

    def create_severity_chart(self, severity_counts: Dict) -> Drawing:
        """Crée un graphique en secteurs pour les sévérités"""
        drawing = Drawing(300, 200)
        
        pie = Pie()
        pie.x = 50
        pie.y = 50
        pie.width = 200
        pie.height = 200
        
        # Données
        data = []
        labels = []
        colors_list = []
        
        color_map = {
            'CRITICAL': colors.red,
            'HIGH': colors.orange,
            'MEDIUM': colors.yellow,
            'LOW': colors.green,
            'INFO': colors.lightblue
        }
        
        for severity, count in severity_counts.items():
            if count > 0:
                data.append(count)
                labels.append(f"{severity}: {count}")
                colors_list.append(color_map.get(severity, colors.grey))
        
        pie.data = data
        pie.labels = labels
        pie.slices.strokeWidth = 0.5
        
        for i, color in enumerate(colors_list):
            pie.slices[i].fillColor = color
        
        drawing.add(pie)
        return drawing

    def export_to_pdf_advanced(self, anomalies: List, filepath: str, 
                              summary: Dict = None) -> bool:
        """Export PDF avancé avec mise en page professionnelle"""
        try:
            doc = SimpleDocTemplate(
                filepath, 
                pagesize=A4,
                rightMargin=72, 
                leftMargin=72,
                topMargin=72, 
                bottomMargin=18
            )
            
            story = []
            
            # === PAGE DE COUVERTURE ===
            story.append(Spacer(1, 2*inch))
            
            # Titre principal
            title = Paragraph("RAPPORT DE SÉCURITÉ DEVSECOPS", self.styles['CustomTitle'])
            story.append(title)
            story.append(Spacer(1, 0.5*inch))
            
            if summary:
                # Informations du rapport
                info_data = [
                    ["Fichier analysé:", summary['workflow_path']],
                    ["Date d'analyse:", summary['analysis_date']],
                    ["Score de sécurité:", f"{summary['security_score']}/100 ({summary['grade']})"],
                    ["Niveau de risque:", summary['risk_level']],
                    ["Total anomalies:", str(summary['total_anomalies'])]
                ]
                
                info_table = Table(info_data, colWidths=[2*inch, 4*inch])
                info_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
                    ('TEXTCOLOR', (0, 0), (0, -1), colors.black),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 12),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black),
                    ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ]))
                
                story.append(info_table)
                story.append(PageBreak())
                
                # === RÉSUMÉ EXÉCUTIF ===
                story.append(Paragraph("RÉSUMÉ EXÉCUTIF", self.styles['CustomSubTitle']))
                
                exec_summary_text = f"""
                L'analyse du workflow GitHub Actions a révélé <b>{summary['total_anomalies']} anomalie(s)</b> 
                de sécurité avec un score global de <b>{summary['security_score']}/100</b> 
                (Grade: <b>{summary['grade']}</b>).
                
                Le niveau de risque est évalué comme <b>{summary['risk_level']}</b>.
                
                Les anomalies critiques ({summary.get('critical_issues', 0)}) et de haute sévérité 
                ({summary.get('high_issues', 0)}) nécessitent une attention immédiate.
                """
                
                exec_para = Paragraph(exec_summary_text, self.styles['ExecutiveSummary'])
                story.append(exec_para)
                story.append(Spacer(1, 0.3*inch))
                
                # Top catégories
                story.append(Paragraph("Top 5 des Catégories Problématiques", self.styles['Heading3']))
                
                cat_data = [["Catégorie", "Nombre d'anomalies"]]
                for category, count in summary['top_categories']:
                    cat_data.append([category, str(count)])
                
                cat_table = Table(cat_data, colWidths=[4*inch, 1.5*inch])
                cat_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.darkblue),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 10),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black),
                    ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.lightgrey, colors.white])
                ]))
                
                story.append(cat_table)
                story.append(PageBreak())
            
            # === ANOMALIES DÉTAILLÉES ===
            story.append(Paragraph("ANOMALIES DÉTAILLÉES", self.styles['CustomSubTitle']))
            
            # Grouper par sévérité
            by_severity = {}
            for anomaly in anomalies:
                severity = anomaly.severity.name
                if severity not in by_severity:
                    by_severity[severity] = []
                by_severity[severity].append(anomaly)
            
            # Ordre de sévérité
            severity_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
            
            for severity in severity_order:
                if severity in by_severity:
                    anomalies_list = by_severity[severity]
                    
                    # Titre de section
                    severity_title = f"🔴 ANOMALIES {severity}" if severity == 'CRITICAL' else \
                                   f"🟠 ANOMALIES {severity}" if severity == 'HIGH' else \
                                   f"🟡 ANOMALIES {severity}" if severity == 'MEDIUM' else \
                                   f"🟢 ANOMALIES {severity}"
                    
                    story.append(Paragraph(severity_title, self.styles['Heading3']))
                    story.append(Spacer(1, 0.2*inch))
                    
                    # Table des anomalies
                    data = [["Job", "Step", "Type", "Détail", "Recommandation"]]
                    
                    for anomaly in anomalies_list:
                        data.append([
                            anomaly.job,
                            anomaly.step,
                            anomaly.type,
                            anomaly.detail[:100] + "..." if len(anomaly.detail) > 100 else anomaly.detail,
                            anomaly.recommendation[:80] + "..." if len(anomaly.recommendation) > 80 else anomaly.recommendation
                        ])
                    
                    # Couleur de fond selon sévérité
                    bg_color = colors.mistyrose if severity == 'CRITICAL' else \
                              colors.moccasin if severity == 'HIGH' else \
                              colors.lightyellow if severity == 'MEDIUM' else \
                              colors.lightgreen
                    
                    table = Table(data, colWidths=[1*inch, 1*inch, 1.5*inch, 2*inch, 2*inch])
                    table.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (-1, 0), colors.darkgrey),
                        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                        ('FONTSIZE', (0, 0), (-1, -1), 8),
                        ('GRID', (0, 0), (-1, -1), 1, colors.black),
                        ('BACKGROUND', (0, 1), (-1, -1), bg_color),
                        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                    ]))
                    
                    story.append(table)
                    story.append(Spacer(1, 0.3*inch))
            
            # Générer le PDF
            doc.build(story)
            return True
            
        except Exception as e:
            print(f"Erreur lors de l'export PDF avancé: {e}")
            return False

    def export_to_excel_advanced(self, anomalies: List, filepath: str, 
                                summary: Dict = None) -> bool:
        """Export Excel avancé avec graphiques et formatage"""
        if not EXCEL_AVAILABLE:
            print("⚠️ xlsxwriter non disponible. Installez avec: pip install xlsxwriter")
            return False
        
        try:
            workbook = xlsxwriter.Workbook(filepath)
            
            # Formats
            title_format = workbook.add_format({
                'bold': True, 'font_size': 16, 'align': 'center',
                'fg_color': '#2F5597', 'font_color': 'white'
            })
            header_format = workbook.add_format({
                'bold': True, 'bg_color': '#D9E1F2', 'border': 1
            })
            critical_format = workbook.add_format({'bg_color': '#FF6B6B'})
            high_format = workbook.add_format({'bg_color': '#FFA500'})
            medium_format = workbook.add_format({'bg_color': '#FFD700'})
            low_format = workbook.add_format({'bg_color': '#90EE90'})
            
            # === FEUILLE RÉSUMÉ ===
            summary_sheet = workbook.add_worksheet('Résumé Exécutif')
            
            if summary:
                # Titre
                summary_sheet.merge_range('A1:F1', 'RAPPORT DE SÉCURITÉ DEVSECOPS', title_format)
                
                # Informations générales
                row = 3
                summary_sheet.write(row, 0, 'Fichier analysé:', header_format)
                summary_sheet.write(row, 1, summary['workflow_path'])
                row += 1
                summary_sheet.write(row, 0, 'Date d\'analyse:', header_format)
                summary_sheet.write(row, 1, summary['analysis_date'])
                row += 1
                summary_sheet.write(row, 0, 'Score de sécurité:', header_format)
                summary_sheet.write(row, 1, f"{summary['security_score']}/100 ({summary['grade']})")
            
            # === FEUILLE ANOMALIES DÉTAILLÉES ===
            details_sheet = workbook.add_worksheet('Anomalies Détaillées')
            
            # En-têtes
            headers = [
                'ID', 'Sévérité', 'Job', 'Step', 'Type', 'Catégorie',
                'Détail', 'Recommandation'
            ]
            
            for col, header in enumerate(headers):
                details_sheet.write(0, col, header, header_format)
            
            # Données avec formatage conditionnel
            for row, anomaly in enumerate(anomalies, 1):
                # Format basé sur la sévérité
                if anomaly.severity.name == 'CRITICAL':
                    row_format = critical_format
                elif anomaly.severity.name == 'HIGH':
                    row_format = high_format
                elif anomaly.severity.name == 'MEDIUM':
                    row_format = medium_format
                else:
                    row_format = low_format
                
                details_sheet.write(row, 0, row, row_format)
                details_sheet.write(row, 1, anomaly.severity.value, row_format)
                details_sheet.write(row, 2, anomaly.job, row_format)
                details_sheet.write(row, 3, anomaly.step, row_format)
                details_sheet.write(row, 4, anomaly.type, row_format)
                details_sheet.write(row, 5, anomaly.category, row_format)
                details_sheet.write(row, 6, anomaly.detail, row_format)
                details_sheet.write(row, 7, anomaly.recommendation, row_format)
            
            # Ajustement automatique des colonnes
            for col in range(len(headers)):
                details_sheet.set_column(col, col, 15)
            
            workbook.close()
            return True
            
        except Exception as e:
            print(f"Erreur lors de l'export Excel: {e}")
            return False

    def export_to_html_dashboard(self, anomalies: List, filepath: str, 
                               summary: Dict = None) -> bool:
        """Génère un dashboard HTML interactif"""
        try:
            html_content = self._generate_html_template(anomalies, summary)
            
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            return True
        except Exception as e:
            print(f"Erreur lors de l'export HTML: {e}")
            return False

    def _generate_html_template(self, anomalies: List, summary: Dict = None) -> str:
        """Génère le template HTML complet"""
        
        severity_counts = {}
        if anomalies:
            for anomaly in anomalies:
                severity = anomaly.severity.name
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        html = f"""
        <!DOCTYPE html>
        <html lang="fr">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Dashboard DevSecOps</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }}
                .container {{ max-width: 1200px; margin: 0 auto; }}
                .header {{ background: #2c3e50; color: white; padding: 20px; border-radius: 5px; margin-bottom: 20px; }}
                .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 20px; }}
                .stat-card {{ background: white; padding: 15px; border-radius: 5px; text-align: center; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }}
                .stat-number {{ font-size: 2em; font-weight: bold; color: #3498db; }}
                .table-container {{ background: white; border-radius: 5px; overflow: hidden; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }}
                table {{ width: 100%; border-collapse: collapse; }}
                th {{ background: #34495e; color: white; padding: 12px; text-align: left; }}
                td {{ padding: 10px; border-bottom: 1px solid #eee; }}
                .critical {{ background-color: #ffebee; }}
                .high {{ background-color: #fff3e0; }}
                .medium {{ background-color: #fffde7; }}
                .low {{ background-color: #e8f5e8; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🔐 Dashboard DevSecOps</h1>
                    <p>Rapport d'analyse de sécurité généré le {self.report_timestamp.strftime('%d/%m/%Y à %H:%M:%S')}</p>
                </div>
                
                <div class="stats">
                    <div class="stat-card">
                        <div class="stat-number">{summary.get('security_score', 0) if summary else 0}/100</div>
                        <div>Score de Sécurité</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">{len(anomalies)}</div>
                        <div>Total Anomalies</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">{severity_counts.get('CRITICAL', 0)}</div>
                        <div>Critiques</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">{severity_counts.get('HIGH', 0)}</div>
                        <div>Élevées</div>
                    </div>
                </div>
                
                <div class="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>Sévérité</th>
                                <th>Job</th>
                                <th>Step</th>
                                <th>Type</th>
                                <th>Détail</th>
                                <th>Recommandation</th>
                            </tr>
                        </thead>
                        <tbody>
        """
        
        for anomaly in anomalies:
            severity_class = anomaly.severity.name.lower()
            html += f"""
                            <tr class="{severity_class}">
                                <td>{anomaly.severity.value}</td>
                                <td>{anomaly.job}</td>
                                <td>{anomaly.step}</td>
                                <td>{anomaly.type}</td>
                                <td>{anomaly.detail}</td>
                                <td>{anomaly.recommendation}</td>
                            </tr>
            """
        
        html += """
                        </tbody>
                    </table>
                </div>
            </div>
        </body>
        </html>
        """
        
        return html

# Fonctions de compatibilité pour l'ancien code
def export_to_csv(anomalies, filepath):
    """Fonction de compatibilité pour l'export CSV basique"""
    generator = AdvancedReportGenerator()
    return generator.export_to_csv(anomalies, filepath)

def export_to_pdf(anomalies, filepath):
    """Fonction de compatibilité pour l'export PDF basique"""
    generator = AdvancedReportGenerator()
    return generator.export_to_pdf(anomalies, filepath)
