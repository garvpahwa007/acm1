"""PhishGuard — a phishing link & email checker with receipts.

Run from the project root:  python3 backend/app.py     (binds 0.0.0.0:8000)
"""
from __future__ import annotations

import json
import os
import traceback

from flask import Flask, jsonify, render_template, request

from engine import emailscan, store, urlscan

MAX_UPLOAD = 12 * 1024 * 1024  # 12 MB .eml ceiling

FRONTEND_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "frontend"))
app = Flask(
    __name__,
    template_folder=os.path.join(FRONTEND_DIR, "templates"),
    static_folder=os.path.join(FRONTEND_DIR, "static"),
)
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD
# Templates/CSS are edited during pilots; never serve a stale cached page.
app.config["TEMPLATES_AUTO_RELOAD"] = True
app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0
store.init()


@app.get("/")
def index():
    return render_template("index.html")


@app.get("/advanced")
def advanced():
    return render_template("advanced.html")


@app.get("/api/health")
def health():
    from engine import intel
    return jsonify({"ok": True, "intel": intel.configured(), "stats": store.stats()})


@app.get("/api/stats")
def stats():
    return jsonify(store.stats())


@app.post("/api/check/url")
def check_url():
    """?mode=quick  -> lexical only (milliseconds)
       ?mode=full   -> + registration/DNS/TLS/reputation/click-preview"""
    data = request.get_json(silent=True) or {}
    url = (data.get("url") or "").strip()
    if not url:
        return jsonify({"error": "no url provided"}), 400
    if len(url) > 4000:
        return jsonify({"error": "url too long"}), 400
    mode = (request.args.get("mode") or data.get("mode") or "full").lower()
    try:
        if mode == "quick":
            result = urlscan.analyze_quick(url)
        else:
            result = urlscan.analyze_full(url, do_preview=data.get("preview", True))
        result["cluster_hint"] = (result.get("facts") or {}).get(
            "registrable_domain") or "unknown"
        return jsonify(result)
    except Exception as exc:
        traceback.print_exc()
        return jsonify({"error": f"{type(exc).__name__}: {exc}"}), 500


@app.post("/api/check/email")
def check_email():
    raw = None
    if "file" in request.files:
        f = request.files["file"]
        raw = f.read()
    else:
        data = request.get_json(silent=True) or {}
        text = data.get("raw") or ""
        if text.strip():
            raw = text.encode("utf-8", "replace")
    if not raw:
        return jsonify({"error": "provide an .eml file or paste raw message source"}), 400
    if len(raw) > MAX_UPLOAD:
        return jsonify({"error": "message too large (12 MB max)"}), 413
    try:
        return jsonify(emailscan.scan_eml(raw))
    except Exception as exc:
        traceback.print_exc()
        return jsonify({"error": f"could not parse message: {type(exc).__name__}: {exc}"}), 400


@app.post("/api/report")
def report():
    """Report-to-sweep: one report protects everyone who got the same mail."""
    data = request.get_json(silent=True) or {}
    cluster = (data.get("cluster_key") or "").strip() or "unknown"
    out = store.add_report(
        cluster_key=cluster,
        subject=(data.get("subject") or "")[:300],
        sender=(data.get("sender") or "")[:200],
        links=data.get("links") or [],
        reporter=(data.get("reporter") or "anonymous")[:60],
        clicked=bool(data.get("clicked")),
        verdict=(data.get("verdict") or "unknown")[:40],
        score=int(data.get("score") or 0),
    )
    return jsonify(out)


SAMPLE_DIR = os.path.join(os.path.dirname(__file__), "samples")


@app.get("/api/sample/<name>")
def sample(name):
    """Built-in demo messages so the app can be evaluated in one click."""
    if not name.isalnum() and "_" not in name:
        return jsonify({"error": "bad name"}), 400
    path = os.path.join(SAMPLE_DIR, f"{name}.eml")
    if not os.path.isfile(path):
        return jsonify({"error": "sample not found"}), 404
    with open(path, "rb") as fh:
        data = fh.read()
    return app.response_class(data, mimetype="text/plain")


@app.post("/api/vendor/confirm")
def vendor_confirm():
    """Only a human, after an out-of-band check, may move a vendor's bank baseline."""
    data = request.get_json(silent=True) or {}
    out = store.confirm_vendor_account((data.get("vendor_key") or "").strip(),
                                       (data.get("by") or "analyst")[:60])
    return jsonify(out), (200 if out.get("ok") else 400)


@app.get("/api/clusters")
def clusters():
    return jsonify({"clusters": store.all_clusters()})


@app.get("/api/receipt/<rid>")
def receipt(rid):
    payload = store.get_receipt(rid)
    if not payload:
        return jsonify({"error": "receipt not found"}), 404
    return app.response_class(json.dumps(payload, indent=2), mimetype="application/json")


@app.get("/api/money-deterred")
def money_deterred():
    """The metric a CFO signs a renewal on: prevented loss, not detections."""
    s = store.stats()
    clusters = store.all_clusters()
    prevented = sum(1 for c in clusters if c["verdict"] == "malicious")
    return jsonify({
        "reports_handled": s["reports"],
        "clusters_neutralised": prevented,
        "people_protected": sum(max(c["reports"] - 1, 0) for c in clusters),
        "est_value_protected_inr": prevented * 185000,
        "method": "est. ₹1.85L average BEC loss per prevented cluster (industry median)",
        "note": "Deliberately conservative: counts only clusters confirmed malicious.",
    })


@app.after_request
def headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    return resp


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8000"))
    app.run(host="0.0.0.0", port=port, debug=False, threaded=True)
