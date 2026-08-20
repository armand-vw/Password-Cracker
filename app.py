"""Flask web app for the password cracker."""
import os
import tempfile
import threading
import uuid

from flask import Flask, jsonify, render_template, request

from cracker import engine, hashes, wordlists

app = Flask(__name__)

# Port chosen to avoid conflicts with existing apps (5000/8000 were in use).
PORT = 5001
HOST = "0.0.0.0"

JOBS = {}
STOP_EVENTS = {}
JOBS_LOCK = threading.Lock()


@app.route("/")
def index():
    return render_template("index.html", schemes=[s.name for s in hashes.SCHEMES])


@app.route("/api/schemes")
def api_schemes():
    return jsonify([s.name for s in hashes.SCHEMES])


@app.route("/api/crack", methods=["POST"])
def api_crack():
    data = request.get_json(silent=True) or {}

    targets = [h.strip() for h in data.get("hashes", []) if h.strip()]
    if not targets:
        return jsonify({"error": "No hashes provided."}), 400

    wordlist_text = data.get("wordlist", "")
    use_sample = data.get("use_sample", False)
    rules = data.get("rules", [])
    scheme_override = data.get("scheme") or None

    if scheme_override and scheme_override not in hashes.SCHEME_NAMES:
        return jsonify({"error": f"Unknown scheme: {scheme_override}"}), 400

    if use_sample:
        wordlist_path = os.path.join(app.root_path, "wordlists", "common-sample.txt")
    elif wordlist_text.strip():
        wordlist_path = _write_temp(wordlist_text)
    else:
        return jsonify({"error": "No wordlist provided."}), 400

    job_id = uuid.uuid4().hex
    stop_event = threading.Event()
    job = {
        "id": job_id,
        "status": "running",
        "tried": 0,
        "found_count": 0,
        "results": [],
        "elapsed": 0.0,
        "message": "",
        "done": False,
    }
    with JOBS_LOCK:
        JOBS[job_id] = job
        STOP_EVENTS[job_id] = stop_event

    def on_progress(tried, found_count):
        job["tried"] = tried
        job["found_count"] = found_count

    def run():
        try:
            result = engine.crack(
                targets,
                wordlists.iter_words(wordlist_path),
                rules,
                scheme_override=scheme_override,
                on_progress=on_progress,
                should_stop=stop_event.is_set,
            )
            job["tried"] = result["tried"]
            job["found_count"] = len(result["results"])
            job["results"] = result["results"]
            job["elapsed"] = round(result["elapsed"], 3)
            job["status"] = "stopped" if stop_event.is_set() else "done"
        except Exception as exc:  # noqa: BLE001
            job["status"] = "error"
            job["message"] = str(exc)
        finally:
            job["done"] = True
            if not use_sample:
                _remove_temp(wordlist_path)

    threading.Thread(target=run, daemon=True).start()
    return jsonify({"job_id": job_id})


@app.route("/api/status/<job_id>")
def api_status(job_id):
    job = JOBS.get(job_id)
    if job is None:
        return jsonify({"error": "Job not found."}), 404
    return jsonify(job)


@app.route("/api/stop/<job_id>", methods=["POST"])
def api_stop(job_id):
    job = JOBS.get(job_id)
    if job is None:
        return jsonify({"error": "Job not found."}), 404
    STOP_EVENTS.get(job_id, threading.Event()).set()
    job["status"] = "stopping"
    return jsonify({"ok": True})


def _write_temp(text):
    fd, path = tempfile.mkstemp(prefix="pwcrack_", suffix=".txt")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)
    return path


def _remove_temp(path):
    try:
        os.remove(path)
    except OSError:
        pass


if __name__ == "__main__":
    app.run(host=HOST, port=PORT, debug=False, threaded=True)
