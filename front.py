import requests
import os
from flask import Blueprint, render_template

frontend_bp = Blueprint(
    "frontend",
    __name__,
    template_folder="templates"
)



def get_latest_release():
    url = os.getenv("LATEST_RELEASE_URL", "#")
    r = requests.get(url, timeout=5)
    r.raise_for_status()
    return r.json()

@frontend_bp.route("/")
def index():
    try:
        release = get_latest_release()

        version = release.get("tag_name", "unknown")

        assets = release.get("assets", [])
        if assets:
            asset = assets[0]
            filename = asset.get("name", "archive.zip")
            download_url = asset.get("browser_download_url", "#")
        else:
            filename = "archive.zip"
            download_url = "#"

    except Exception:
        # fallback, чтобы фронт не умирал
        version = "unknown"
        filename = "archive.zip"
        download_url = "#"

    return render_template(
        "index.html",
        version=version,
        filename=filename,
        download_url=download_url
    )
