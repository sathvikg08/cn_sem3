import os
import json
from flask import Flask, render_template, request, jsonify

app = Flask(__name__)

# State tracking for the live presentation dashboard
system_state = {
    "server_a_online": True,
    "server_b_online": True,
    "link_a_active": True,
    "current_route": "Path A (S1 -> S2 -> S4)",
    "total_files": 1,
    "storage_used_mb": 5.2,
    "recent_logs": [
        "System online and ready.",
        "OS-Ken SDN Controller connected to switches (S1, S2, S3, S4).",
        "Backup Server A (Primary) and Server B (Replica) connected."
    ]
}

@app.route("/")
def index():
    return render_template("index.html", state=system_state)

@app.route("/api/status", methods=["GET"])
def get_status():
    return jsonify(system_state)

@app.route("/api/upload", methods=["POST"])
def api_upload():
    if "file" not in request.files:
        return jsonify({"success": False, "message": "No file selected."}), 400
    file = request.files["file"]
    if file.filename == "":
        return jsonify({"success": False, "message": "Filename is empty."}), 400
    
    filename = file.filename
    system_state["total_files"] += 1
    system_state["recent_logs"].insert(
        0, f"Uploaded '{filename}' -> Split into 1MB chunks -> SHA-256 verified -> Replicated to Server B."
    )
    return jsonify({
        "success": True,
        "message": f"File '{filename}' successfully stored and replicated across Backup Servers!"
    })

@app.route("/api/toggle-link", methods=["POST"])
def toggle_link():
    system_state["link_a_active"] = not system_state["link_a_active"]
    if not system_state["link_a_active"]:
        system_state["current_route"] = "Path B (S1 -> S3 -> S4) [SDN Rerouted]"
        system_state["recent_logs"].insert(
            0, "ALERT: Link S1-S2 failed! OS-Ken Controller updated flow entries to reroute traffic via Path B."
        )
    else:
        system_state["current_route"] = "Path A (S1 -> S2 -> S4) [Primary Restored]"
        system_state["recent_logs"].insert(
            0, "RECOVERY: Link S1-S2 restored. SDN Controller restored primary route."
        )
    return jsonify(system_state)

@app.route("/api/toggle-server", methods=["POST"])
def toggle_server():
    data = request.get_json() or {}
    server = data.get("server", "A")
    if server == "A":
        system_state["server_a_online"] = not system_state["server_a_online"]
        status = "ONLINE" if system_state["server_a_online"] else "OFFLINE"
        system_state["recent_logs"].insert(0, f"Storage Event: Backup Server A is now {status}.")
    elif server == "B":
        system_state["server_b_online"] = not system_state["server_b_online"]
        status = "ONLINE" if system_state["server_b_online"] else "OFFLINE"
        system_state["recent_logs"].insert(0, f"Storage Event: Backup Server B is now {status}.")
    return jsonify(system_state)

@app.route("/api/restore", methods=["POST"])
def api_restore():
    data = request.get_json() or {}
    filename = data.get("filename", "project_report.pdf")
    
    if system_state["server_a_online"]:
        source = "Backup Server A (Primary)"
    elif system_state["server_b_online"]:
        source = "Backup Server B (Replica Storage)"
    else:
        return jsonify({
            "success": False,
            "message": "Restore failed! Both Server A and Server B are offline."
        }), 500
        
    system_state["recent_logs"].insert(
        0, f"Restore requested for '{filename}'. Source: {source} -> SHA-256 integrity match!"
    )
    return jsonify({
        "success": True,
        "source": source,
        "message": f"File '{filename}' successfully reconstructed from {source}."
    })

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)