import json
import shutil
import tempfile
import traceback
from flask import Blueprint, redirect, request, send_file, session, url_for, jsonify
from flask_cors import cross_origin
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
import os
from werkzeug.utils import secure_filename
from googleapiclient.http import MediaFileUpload
from googleapiclient.discovery import build

 
auth_bp = Blueprint("auth", __name__)

FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:5173")

# Allow HTTP for local testing
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

# Load credentials from environment
CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
REDIRECT_URI = os.getenv("REDIRECT_URI")

# Define the required OAuth scopes
SCOPES = [
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile",
    "openid",
    "https://www.googleapis.com/auth/drive.metadata.readonly",
    "https://www.googleapis.com/auth/drive"

]

# OAuth client config
client_config = {
    "web": {
        "client_id": CLIENT_ID,
        "project_id": "safedrive",
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://oauth2.googleapis.com/token",
        "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
        "client_secret": CLIENT_SECRET,
        "redirect_uris": [REDIRECT_URI]
    }
}
def update_metadata(file_name, status="unverified", encrypted=False, flags=0):
    """
    Update or create metadata.json entry for a file.
    file_name: name without extension
    """
    metadata_path = os.path.join("data_storage", "metadata.json")

    # Load existing metadata
    if os.path.exists(metadata_path):
        try:
            with open(metadata_path, "r") as f:
                metadata = json.load(f)
        except Exception:
            metadata = {}
    else:
        metadata = {}

    # Update metadata entry
    metadata[file_name] = {
        "status": status,
        "encrypted": encrypted,
        "flags": flags
    }

    # Save back
    with open(metadata_path, "w") as f:
        json.dump(metadata, f, indent=2)


def format_size(bytes_val):
    gb = bytes_val / (1024 ** 3)
    return f"{gb:.2f} GB"


@auth_bp.route("/login")
def login():

    flow = Flow.from_client_config(
        client_config=client_config,
        scopes=SCOPES,
        redirect_uri=REDIRECT_URI
    )
    authorization_url, state = flow.authorization_url(
        access_type="offline",
        include_granted_scopes="true",
        prompt="consent select_account"  
    )
    session["state"] = state
    return redirect(authorization_url)


@auth_bp.route("/callback")
def callback():
    state = session["state"]

    flow = Flow.from_client_config(
        client_config=client_config,
        scopes=SCOPES,
        state=state,
        redirect_uri=REDIRECT_URI
    )

    flow.fetch_token(authorization_response=request.url)

    credentials = flow.credentials
    session["credentials"] = {
        "token": credentials.token,
        "refresh_token": credentials.refresh_token,
        "token_uri": credentials.token_uri,
        "client_id": credentials.client_id,
        "client_secret": credentials.client_secret,
        "scopes": credentials.scopes
    }

    try:
        creds = Credentials(**session["credentials"])
        user_service = build("oauth2", "v2", credentials=creds)
        drive_service = build("drive", "v3", credentials=creds)

        user_info = user_service.userinfo().get().execute()
        drive_info = drive_service.about().get(fields="storageQuota").execute()
        used = int(drive_info['storageQuota']['usage'])
        total = int(drive_info['storageQuota']['limit'])

        session["user"] = {
            "name": user_info.get("name"),
            "email": user_info.get("email"),
            "avatar": user_info.get("picture"),
            "storageUsed": format_size(used),
            "storageTotal": format_size(total)

        }

        return redirect(FRONTEND_URL)  
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@auth_bp.route("/user")
def get_user():
    user = session.get("user")
    if not user:
        return jsonify({"error": "Not authenticated"}), 401
    return jsonify(user)

@auth_bp.route("/logout")
def logout():
    session.clear()
    return jsonify({"message": "Logged out"})

@auth_bp.route("/drive")
def list_drive_files():
    if "credentials" not in session:
        return redirect(url_for("auth.login"))

    creds_data = session["credentials"]

    credentials = Credentials(
        token=creds_data["token"],
        refresh_token=creds_data["refresh_token"],
        token_uri=creds_data["token_uri"],
        client_id=creds_data["client_id"],
        client_secret=creds_data["client_secret"],
        scopes=creds_data["scopes"]
    )

    try:
        # Build Google Drive service
        service = build("drive", "v3", credentials=credentials)

        # Get up to 20 files
        results = service.files().list(
            pageSize=20,
            fields="files(id, name, mimeType, size, modifiedTime)"
        ).execute()

        files = results.get("files", [])

        # Load global metadata
        metadata_path = os.path.join("data_storage", "metadata.json")
        metadata = {}
        if os.path.exists(metadata_path):
            try:
                with open(metadata_path, "r") as f:
                    metadata = json.load(f)
            except Exception:
                metadata = {}

        enriched_files = []
        for f in files:
            name_no_ext = os.path.splitext(f["name"])[0]
            meta = metadata.get(name_no_ext, {
                "status": "unverified",
                "encrypted": False,
                "flags": 0
            })
            enriched_files.append({
                "id": f["id"],
                "name": f["name"],
                "size": f.get("size", 0),
                "modifiedTime": f.get("modifiedTime", ""),
                "status": meta.get("status", "unverified"),
                "encrypted": meta.get("encrypted", False),
                "flags": meta.get("flags", 0)
            })

        return jsonify(enriched_files)

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@auth_bp.route("/delete/<file_id>", methods=["DELETE"])
def delete_file(file_id):
    creds_data = session.get("credentials")
    if not creds_data:
        return jsonify({"error": "Not authenticated"}), 401

    try:
        credentials = Credentials(
            token=creds_data["token"],
            refresh_token=creds_data.get("refresh_token"),
            token_uri=creds_data["token_uri"],
            client_id=creds_data["client_id"],
            client_secret=creds_data["client_secret"],
            scopes=creds_data["scopes"]
        )

        service = build("drive", "v3", credentials=credentials)
        service.files().delete(fileId=file_id).execute()
        return jsonify({"message": "File deleted successfully"}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@auth_bp.route("/upload_folder_to_drive/<folder_name>", methods=["POST"])
@cross_origin(supports_credentials=True)
def upload_folder_to_drive(folder_name):
    creds_data = session.get("credentials")
    if not creds_data:
        return jsonify({"error": "Not authenticated"}), 401

    folder_path = os.path.join("data_storage", folder_name)
    if not os.path.exists(folder_path):
        return jsonify({"error": "Folder not found"}), 404

    try:
        credentials = Credentials(
            token=creds_data["token"],
            refresh_token=creds_data.get("refresh_token"),
            token_uri=creds_data["token_uri"],
            client_id=creds_data["client_id"],
            client_secret=creds_data["client_secret"],
            scopes=creds_data["scopes"]
        )

        # Build service with longer timeout
        import httplib2
        from google_auth_httplib2 import AuthorizedHttp
        http = httplib2.Http(timeout=300)
        authed_http = AuthorizedHttp(credentials, http=http)
        service = build("drive", "v3", http=authed_http)

        # Zip the folder
        zip_path = shutil.make_archive(folder_path, 'zip', folder_path)
        zip_filename = os.path.basename(zip_path)

        # Resumable upload
        media = MediaFileUpload(zip_path, mimetype="application/zip", resumable=True)
        metadata = {
            "name": zip_filename,
            "mimeType": "application/zip"
        }

        request_upload = service.files().create(
            body=metadata,
            media_body=media,
            fields="id, name, webViewLink"
        )

        response = None
        while response is None:
            status, response = request_upload.next_chunk()
            if status:
                print(f"Upload progress: {int(status.progress() * 100)}%")

        # Clean up local zip
        media._fd.close()
        os.remove(zip_path)

        return jsonify({
            "message": "Folder zipped and uploaded successfully",
            "file_id": response.get("id"),
            "name": response.get("name"),
            "link": response.get("webViewLink")
        }), 200

    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

@auth_bp.route("/save_safe_file", methods=["POST"])
@cross_origin(supports_credentials=True)
def save_safe_file():
    from app import update_global_metadata

    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files["file"]
    name, ext = os.path.splitext(file.filename)
    folder_path = os.path.join("data_storage", name)

    # Clean and recreate folder
    if os.path.exists(folder_path):
        shutil.rmtree(folder_path)
    os.makedirs(folder_path, exist_ok=True)

    safe_path = os.path.join(folder_path, f"{file.filename}")
    file.save(safe_path)

    # Save metadata.json inside the safe file's folder
    metadata_path = os.path.join(folder_path, "metadata.json")
    with open(metadata_path, "w") as meta_f:
        json.dump({
            "status": "safe",
            "encrypted": False,
            "flags": 0
        }, meta_f)

    # Update global metadata so dashboard displays correctly
    update_global_metadata(
        name,                 # base name (without extension)
        status="safe",
        encrypted=False,
        flags=0               # no sensitive zones
    )

    # Return actual saved path (original filename)
    return jsonify({
        "message": "Safe file stored successfully",
        "folder": name,
        "safe_file": os.path.abspath(safe_path)
    }), 200


@auth_bp.route("/upload_single_to_drive", methods=["POST"])
@cross_origin(supports_credentials=True)
def upload_single_to_drive():
    """
    Expects JSON body:
    {
        "file_path": "data_storage/<folder>/<file>"
    }
    """
    creds_data = session.get("credentials")
    if not creds_data:
        return jsonify({"error": "Not authenticated"}), 401

    data = request.get_json()
    if not data or "file_path" not in data:
        return jsonify({"error": "File path required"}), 400

    file_path = data["file_path"]

    # Normalize relative path
    if not os.path.isabs(file_path):
        file_path = os.path.abspath(file_path)

    if not os.path.exists(file_path):
        return jsonify({"error": f"File not found: {file_path}"}), 404

    try:
        credentials = Credentials(
            token=creds_data["token"],
            refresh_token=creds_data.get("refresh_token"),
            token_uri=creds_data["token_uri"],
            client_id=creds_data["client_id"],
            client_secret=creds_data["client_secret"],
            scopes=creds_data["scopes"]
        )

        # Build service with longer timeout
        import httplib2
        from google_auth_httplib2 import AuthorizedHttp
        http = httplib2.Http(timeout=300)  # 5 min
        authed_http = AuthorizedHttp(credentials, http=http)
        service = build("drive", "v3", http=authed_http)

        # Prepare metadata
        metadata = {"name": os.path.basename(file_path)}

        # Resumable upload
        media = MediaFileUpload(file_path, resumable=True)
        request_upload = service.files().create(
            body=metadata,
            media_body=media,
            fields="id, name, webViewLink"
        )

        response = None
        while response is None:
            status, response = request_upload.next_chunk()
            if status:
                print(f"Upload progress: {int(status.progress() * 100)}%")

        return jsonify({
            "message": "File uploaded successfully",
            "file_id": response.get("id"),
            "name": response.get("name"),
            "link": response.get("webViewLink")
        }), 200

    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

@auth_bp.route("/download/<file_id>", methods=["GET"])
@cross_origin(supports_credentials=True)
def download_drive_file(file_id):
    creds_data = session.get("credentials")
    if not creds_data:
        return jsonify({"error": "Not authenticated"}), 401

    try:
        credentials = Credentials(
            token=creds_data["token"],
            refresh_token=creds_data["refresh_token"],
            token_uri=creds_data["token_uri"],
            client_id=creds_data["client_id"],
            client_secret=creds_data["client_secret"],
            scopes=creds_data["scopes"]
        )

        service = build("drive", "v3", credentials=credentials)

        # Get file metadata
        file_meta = service.files().get(fileId=file_id, fields="name, mimeType").execute()

        # Download file content
        from googleapiclient.http import MediaIoBaseDownload
        import io
        fh = io.BytesIO()
        request = service.files().get_media(fileId=file_id)
        downloader = MediaIoBaseDownload(fh, request)
        done = False
        while done is False:
            status, done = downloader.next_chunk()

        fh.seek(0)
        return send_file(
            fh,
            as_attachment=True,
            download_name=file_meta["name"],
            mimetype=file_meta["mimeType"]
        )

    except Exception as e:
        return jsonify({"error": str(e)}), 500
