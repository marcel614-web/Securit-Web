#!/usr/bin/env python3
"""
Serveur Web Flask pour SSL Scanner
Interface web type SSL Labs
"""

import json
import threading
from datetime import datetime
from flask import Flask, render_template, request, jsonify
from dataclasses import asdict

from ssl_scanner import SSLScanner, ScanResult

app = Flask(__name__)

# ── Stockage en mémoire des scans récents ──
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
        # Limiter l'historique
        if len(scan_history) > MAX_HISTORY:
            oldest_key = next(iter(scan_history))
            del scan_history[oldest_key]


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/scan", methods=["POST"])
def api_scan():
    """Lance un scan SSL et retourne les résultats en JSON."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "Corps JSON requis"}), 400

    host = data.get("host", "").strip().rstrip("/")
    if not host:
        return jsonify({"error": "Champ 'host' requis"}), 400

    # Nettoyer l'URL
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
    """Retourne l'historique des scans récents."""
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
    """Scan via GET pour faciliter les tests."""
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


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="SSL Scanner Web Server")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()
    print(f"[*] SSL Scanner Web UI démarré sur http://{args.host}:{args.port}")
    app.run(host=args.host, port=args.port, debug=args.debug)