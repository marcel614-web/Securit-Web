"""
pdf_generator.py – Génération d'un rapport PDF résumé pour SSL Scanner.
Utilise fpdf2 (pip install fpdf2).
"""

from fpdf import FPDF
from ssl_scanner import ScanResult

def generate_pdf_report(result: ScanResult, output_path: str):
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    pdf.set_font("Helvetica", size=10)
    pdf.set_font("Helvetica", style="B", size=16)
    pdf.cell(0, 10, "Rapport d'analyse SSL/TLS", ln=True, align="C")
    pdf.set_font("Helvetica", size=10)
    pdf.cell(0, 6, f"Généré le {result.scan_time}", ln=True, align="C")
    pdf.ln(5)

    pdf.set_font("Helvetica", style="B", size=13)
    pdf.cell(0, 8, "Informations générales", ln=True)
    pdf.set_font("Helvetica", size=10)
    pdf.cell(40, 6, "Hôte :")
    pdf.cell(0, 6, f"{result.host}:{result.port}", ln=True)
    pdf.cell(40, 6, "IP :")
    pdf.cell(0, 6, result.ip_address, ln=True)
    pdf.cell(40, 6, "Score :")
    pdf.cell(0, 6, f"{result.score}/100  (Note : {result.grade})", ln=True)
    pdf.cell(40, 6, "Durée :")
    pdf.cell(0, 6, f"{result.duration_ms} ms", ln=True)
    pdf.ln(4)

    if result.errors:
        pdf.set_font("Helvetica", style="B", size=12)
        pdf.cell(0, 8, "Erreurs", ln=True)
        pdf.set_font("Helvetica", size=10)
        for e in result.errors:
            pdf.multi_cell(0, 5, f"- {e}")
        pdf.ln(2)

    if result.warnings:
        pdf.set_font("Helvetica", style="B", size=12)
        pdf.cell(0, 8, "Avertissements", ln=True)
        pdf.set_font("Helvetica", size=10)
        for w in result.warnings:
            pdf.multi_cell(0, 5, f"- {w}")
        pdf.ln(4)

    if result.certificate:
        cert = result.certificate
        pdf.set_font("Helvetica", style="B", size=13)
        pdf.cell(0, 8, "Certificat", ln=True)
        pdf.set_font("Helvetica", size=10)
        info = [
            ("CN (sujet)", cert.subject.get("CN", "N/A")),
            ("Émetteur", cert.issuer.get("O", cert.issuer.get("CN", "N/A"))),
            ("Algorithme", cert.signature_algorithm),
            ("Type de clé", f"{cert.key_type} {cert.key_bits} bits"),
            ("Expiration", cert.not_after),
            ("Jours restants", str(cert.days_until_expiry)),
            ("Auto-signé", "Oui" if cert.is_self_signed else "Non"),
        ]
        for label, value in info:
            pdf.cell(45, 6, f"{label} :")
            pdf.cell(0, 6, value, ln=True)
        if cert.san:
            pdf.cell(45, 6, "SAN :")
            pdf.multi_cell(0, 6, ", ".join(cert.san[:6]) + (f" +{len(cert.san)-6}" if len(cert.san)>6 else ""))
        pdf.ln(4)

    if result.protocol_support:
        proto = result.protocol_support
        pdf.set_font("Helvetica", style="B", size=13)
        pdf.cell(0, 8, "Protocoles", ln=True)
        pdf.set_font("Helvetica", size=10)
        for name, supported in [("TLS 1.3", proto.tls13), ("TLS 1.2", proto.tls12),
                                ("TLS 1.1", proto.tls11), ("TLS 1.0", proto.tls10),
                                ("SSLv3", proto.ssl3), ("SSLv2", proto.ssl2)]:
            pdf.cell(60, 6, f"{name} : {'Activé' if supported else 'Inactif'}", ln=True)
        pdf.ln(4)

    if result.cipher_suites:
        pdf.set_font("Helvetica", style="B", size=13)
        pdf.cell(0, 8, "Suites de chiffrement (top 5)", ln=True)
        pdf.set_font("Helvetica", size=10)
        for cs in result.cipher_suites[:5]:
            pdf.cell(0, 5, f"- {cs.name} ({cs.bits} bits) [{cs.strength}]", ln=True)
        pdf.ln(4)

    vulns = [v for v in result.vulnerabilities if v.vulnerable and v.severity in ("critical", "high", "medium")]
    if vulns:
        pdf.set_font("Helvetica", style="B", size=13)
        pdf.cell(0, 8, "Vulnérabilités détectées", ln=True)
        pdf.set_font("Helvetica", size=10)
        for v in vulns:
            pdf.cell(0, 6, f"- [{v.severity.upper()}] {v.name}", ln=True)
            pdf.multi_cell(0, 5, f"  {v.description}")
            pdf.ln(1)
        pdf.ln(4)

    if result.security_headers:
        sh = result.security_headers
        pdf.set_font("Helvetica", style="B", size=13)
        pdf.cell(0, 8, "Sécurité HTTP (HSTS)", ln=True)
        pdf.set_font("Helvetica", size=10)
        if sh.hsts:
            pdf.cell(0, 6, f"HSTS actif, max-age = {sh.hsts_max_age}s", ln=True)
            pdf.cell(0, 6, f"includeSubDomains : {'Oui' if sh.hsts_include_subdomains else 'Non'}", ln=True)
            pdf.cell(0, 6, f"preload           : {'Oui' if sh.hsts_preload else 'Non'}", ln=True)
        else:
            pdf.cell(0, 6, "HSTS absent", ln=True)
        pdf.ln(4)

    pdf.ln(10)
    pdf.set_font("Helvetica", style="I", size=8)
    pdf.cell(0, 6, "Rapport généré par SSL Scanner v2.4", align="C")
    pdf.output(output_path)