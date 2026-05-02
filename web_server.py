#!/usr/bin/env python3
"""
Serveur Web Flask pour SSL Scanner
Ajouts : endpoint de téléchargement PDF
"""

import json
import threading
import io
import tempfile
import os
from datetime import datetime
from flask import Flask, render_template, request, jsonify, Response
from dataclasses import asdict

from ssl_scanner import SSLScanner, ScanResult
from pdf_generator import generate_pdf_report

app = Flask(__name__)

scan_history: dict = {}
scan_history_lock = threading.Lock()
MAX_HISTORY = 50


def store_result(result: ScanResult):
    key = f"{result.host}:{result.port}"
    with scan_history_lock:
        scan_history[key] = {
            "result": asdict(result),
            "timestamp": datetime.utcnow().isoformat()
        }
        if len(scan_history) > MAX_HISTORY:
            oldest_key = next(iter(scan_history))
            del scan_history[oldest_key]


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/scan", methods=["POST"])
def api_scan():
    data = request.get_json()
    if not data:
        return jsonify({"error": "Corps JSON requis"}), 400
    host = data.get("host", "").strip().rstrip("/")
    if not host:
        return jsonify({"error": "Champ 'host' requis"}), 400
    if "://" in host:
        host = host.split("://", 1)[1]
    if "/" in host:
        host = host.split("/")[0]
    try:
        port = int(data.get("port", 443))
        if not (1 <= port <= 65535):
            raise ValueError()
    except (ValueError, TypeError):
        return jsonify({"error": "Port invalide (1-65535)"}), 400

    check_protocols = data.get("check_protocols", True)
    check_headers = data.get("check_headers", True)
    timeout = min(float(data.get("timeout", 15.0)), 30.0)

    scanner = SSLScanner(timeout=timeout,
                         check_protocols=check_protocols,
                         check_headers=check_headers)
    try:
        result = scanner.scan(host, port)
        store_result(result)
        return jsonify(asdict(result))
    except Exception as e:
        return jsonify({"error": f"Erreur interne: {str(e)}"}), 500


@app.route("/api/history", methods=["GET"])
def api_history():
    with scan_history_lock:
        history = [
            {
                "host": data["result"]["host"],
                "port": data["result"]["port"],
                "grade": data["result"]["grade"],
                "score": data["result"]["score"],
                "timestamp": data["timestamp"]
            }
            for key, data in list(scan_history.items())[-10:]
        ]
    return jsonify(list(reversed(history)))


@app.route("/api/scan/<path:host>", methods=["GET"])
def api_scan_get(host):
    port = int(request.args.get("port", 443))
    timeout = min(float(request.args.get("timeout", 15)), 30)
    check_protocols = request.args.get("protocols", "1") != "0"
    check_headers = request.args.get("headers", "1") != "0"
    scanner = SSLScanner(timeout=timeout,
                         check_protocols=check_protocols,
                         check_headers=check_headers)
    try:
        result = scanner.scan(host, port)
        store_result(result)
        return jsonify(asdict(result))
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/scan/download", methods=["GET"])
def api_scan_download():
    """Télécharge le dernier scan pour un hôte donné (JSON)."""
    host = request.args.get("host", "")
    port = int(request.args.get("port", 443))
    key = f"{host}:{port}"
    with scan_history_lock:
        entry = scan_history.get(key)
    if not entry:
        return jsonify({"error": "Aucun scan trouvé pour cet hôte/port dans l'historique."}), 404
    result_json = json.dumps(entry["result"], indent=2, default=str)
    return Response(
        result_json,
        mimetype="application/json",
        headers={"Content-Disposition": f"attachment;filename=ssl_scan_{host}_{port}.json"}
    )


@app.route("/api/scan/pdf", methods=["GET"])
def api_scan_pdf():
    """Génère et télécharge un rapport PDF pour un scan récent."""
    host = request.args.get("host", "")
    port = int(request.args.get("port", 443))
    key = f"{host}:{port}"
    with scan_history_lock:
        entry = scan_history.get(key)
    if not entry:
        return jsonify({"error": "Aucun scan trouvé pour cet hôte/port dans l'historique."}), 404

    # Reconstruction du ScanResult depuis le dictionnaire
    from ssl_scanner import CertificateInfo, ProtocolSupport, SecurityHeaders, CipherSuite, VulnerabilityCheck

    def _dict_to_dataclass(cls, d):
        if d is None: return None
        try:
            return cls(**d)
        except:
            return None

    result_dict = entry["result"]
    cert = _dict_to_dataclass(CertificateInfo, result_dict.get("certificate"))
    proto = _dict_to_dataclass(ProtocolSupport, result_dict.get("protocol_support"))
    headers = _dict_to_dataclass(SecurityHeaders, result_dict.get("security_headers"))
    ciphers = [cs for cs in (_dict_to_dataclass(CipherSuite, cs) for cs in result_dict.get("cipher_suites", [])) if cs]
    vulns = [v for v in (_dict_to_dataclass(VulnerabilityCheck, v) for v in result_dict.get("vulnerabilities", [])) if v]

    result = ScanResult(
        host=result_dict["host"],
        port=result_dict["port"],
        ip_address=result_dict.get("ip_address", "N/A"),
        scan_time=result_dict.get("scan_time", "N/A"),
        duration_ms=result_dict.get("duration_ms", 0.0),
        grade=result_dict.get("grade", "N/A"),
        score=result_dict.get("score", 0),
        certificate=cert,
        protocol_support=proto,
        cipher_suites=ciphers,
        security_headers=headers,
        vulnerabilities=vulns,
        errors=result_dict.get("errors", []),
        warnings=result_dict.get("warnings", [])
    )

    # Générer le PDF dans un fichier temporaire
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pdf") as tmp:
            generate_pdf_report(result, tmp.name)
            tmp.flush()
            with open(tmp.name, "rb") as f:
                pdf_bytes = f.read()
        os.unlink(tmp.name)
    except Exception as e:
        return jsonify({"error": f"Erreur lors de la génération du PDF : {str(e)}"}), 500

    return Response(
        pdf_bytes,
        mimetype="application/pdf",
        headers={"Content-Disposition": f"attachment;filename=ssl_scan_{host}_{port}.pdf"}
    )


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="SSL Scanner Web Server")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()
    print(f"[*] SSL Scanner Web UI démarré sur http://{args.host}:{args.port}")
    app.run(host=args.host, port=args.port, debug=args.debug)