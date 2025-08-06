import shutil
import tempfile
import time
import zipfile
from flask import Flask, send_file, send_from_directory , session, jsonify ,request
from routes.sensitive_image_detection import (
    detect_and_process_sensitive_data,
    is_image_file,
    encrypt_text,
    decrypt_text,
    mask_sensitive_zones,
    fit_text_in_bbox,
    get_text_position_in_bbox,
)
from routes.sensitive_files_detection import (
    auto_detect_and_process,
    encrypt_sensitive_data,
    decrypt_document,
    detect_file_type,
    mask_csv_file,
    mask_docx_file,
    mask_txt_file,
    mask_xlsx_file,
    blur_sensitive_pdf,
    get_ctx,
    setup_context
)

import os
from flask_cors import CORS, cross_origin
from dotenv import load_dotenv
import os
import cv2
import json
from cryptography.fernet import Fernet
import numpy as np
import easyocr
import tenseal as ts


load_dotenv()

app = Flask(__name__)
app.secret_key = os.urandom(24) 
CORS(app, origins=["http://localhost:5173"], supports_credentials=True)

DATA_FOLDER = "data_storage"
os.makedirs(DATA_FOLDER, exist_ok=True)


# Charge le modèle de détection de visages OpenCV
face_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + "haarcascade_frontalface_default.xml")
# Initialise EasyOCR pour le texte (fr + en)
reader = easyocr.Reader(['en', 'fr'], gpu=False)

def is_image_file(filename):
    return filename.lower().endswith(('.png', '.jpg', '.jpeg', '.bmp', '.gif'))
def update_global_metadata(file_name, status, encrypted=False, flags=0):
    """
    Update central metadata.json in data_storage
    """
    metadata_path = os.path.join(DATA_FOLDER, "metadata.json")

    # Load
    if os.path.exists(metadata_path):
        try:
            with open(metadata_path, "r") as f:
                metadata = json.load(f)
        except Exception:
            metadata = {}
    else:
        metadata = {}

    # Update entry
    metadata[file_name] = {
        "status": status,
        "encrypted": encrypted,
        "flags": flags
    }

    # Save back
    with open(metadata_path, "w") as f:
        json.dump(metadata, f, indent=2)

from routes.auth import auth_bp, update_metadata
app.register_blueprint(auth_bp, url_prefix="/auth")


@app.route('/auth/user')
def get_user_info():
    user = session.get('user')
    if not user:
        return jsonify({'error': 'Not authenticated'}), 401
    return jsonify(user)

@app.route("/encrypt_full", methods=["POST"])
def encrypt_full_image_api():
    if "file" not in request.files:
        return jsonify({"error": "Aucun fichier envoyé"}), 400
    file = request.files["file"]
    if not is_image_file(file.filename):
        return jsonify({"error": "Fichier non image"}), 400

    name, ext = os.path.splitext(file.filename)
    save_dir = os.path.join(DATA_FOLDER, f"{name}_full")
    os.makedirs(save_dir, exist_ok=True)
    img_path = os.path.join(save_dir, f"original{ext}")
    file.save(img_path)

    # Charger et normaliser l'image (grayscale ou RGB)
    img = cv2.imread(img_path, cv2.IMREAD_GRAYSCALE)  # ou IMREAD_COLOR pour RGB
    if img is None:
        return jsonify({"error": "Erreur de lecture image"}), 400
 
    img = cv2.imread(img_path, cv2.IMREAD_COLOR)         # Charge l'image en couleur (BGR)
    img = cv2.cvtColor(img, cv2.COLOR_BGR2RGB)           # Conversion en RGB pour cohérence
    img = img.astype(np.float32) / 255.0                 # Normalise entre 0 et 1
    img_flat = img.flatten().tolist()                    # On aplatit pour CKKS
    shape = img.shape                                    # On garde la shape exacte (H,W,3)
     # Générer contexte TenSEAL
    context = ts.context(
        ts.SCHEME_TYPE.CKKS,
        poly_modulus_degree=8192,
        coeff_mod_bit_sizes=[60, 40, 40, 60]
    )
    context.global_scale = 2**40     # <= Ajoute cette ligne !
    context.generate_galois_keys()
    context.generate_relin_keys()


    # Sérialiser contexte (pour déchiffrement plus tard)
    context_path = os.path.join(save_dir, "context.tseal")
    with open(context_path, "wb") as f:
        f.write(context.serialize(save_public_key=True, save_secret_key=True, save_galois_keys=True, save_relin_keys=True))

    # Chiffrer l'image entière en CKKS vector
    enc_vec = ts.ckks_vector(context, img_flat)
    enc_img_path = os.path.join(save_dir, "full_encrypted.tseal")
    with open(enc_img_path, "wb") as f:
        f.write(enc_vec.serialize())

    return jsonify({
        "message": "Image entière chiffrée homomorphiquement (TenSEAL CKKS)",
        "folder": f"{name}_full",
        "encrypted_file": enc_img_path,
        "context_file": context_path,
        "shape": img.shape
    })

@app.route("/decrypt_full", methods=["POST"])
def decrypt_full_cipher_api():
    """
    Body attendu (multipart/form-data):
      - file: fichier chiffré (binary)
      - context: contexte TenSEAL (binary)
      - shape: shape de l'image originale (ex: 128,128,3)
    """
    if "file" not in request.files or "context" not in request.files or "shape" not in request.form:
        return jsonify({"error": "Fichier chiffré, contexte et shape requis"}), 400

    cipher_file = request.files["file"]
    context_file = request.files["context"]
    shape = tuple(map(int, request.form["shape"].split(",")))

    encrypted_bytes = cipher_file.read()
    context_bytes = context_file.read()
    context = ts.context_from(context_bytes)
    enc_vec = ts.ckks_vector_from(context, encrypted_bytes)

    # Déchiffrer
    decrypted = np.array(enc_vec.decrypt())
    # Précaution pour float: clip entre 0 et 1, puis remise en uint8
    img = np.clip(decrypted, 0, 1) * 255
    img = img.reshape(shape).astype(np.uint8)
    img = cv2.cvtColor(img, cv2.COLOR_RGB2BGR)   # Pour sauvegarder au format OpenCV

    out_dir = os.path.join(DATA_FOLDER, "full_decrypt_cipher")
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, "restored.png")
    cv2.imwrite(out_path, img)

    return jsonify({
        "message": "Image déchiffrée depuis chiffré homomorphe",
        "restored_file": out_path,
        "extension": ".png"
    })

@app.route("/encrypt", methods=["POST"])
def encrypt_image_api():
    if "file" not in request.files:
        return jsonify({"error": "Aucun fichier envoyé"}), 400
    file = request.files["file"]
    if not is_image_file(file.filename):
        return jsonify({"error": "Fichier non image"}), 400
    name, ext = os.path.splitext(file.filename)
    save_dir = os.path.join(DATA_FOLDER, name)

    if os.path.exists(save_dir):
        import gc
        gc.collect()  # force release of any lingering file handles
        try:
            shutil.rmtree(save_dir)
        except PermissionError:
            time.sleep(0.5)
            shutil.rmtree(save_dir)

    os.makedirs(save_dir, exist_ok=True)

    tmp = os.path.join(save_dir, f"tmp{ext}")
    file.save(tmp)

    zones, img = detect_and_process_sensitive_data(
        tmp,
        conf_thresh=0.3,
        use_tesseract=request.form.get("use_tesseract", "false").lower() == "true"
    )
    os.remove(tmp)

    if not zones:
        return jsonify({"message": "Aucune donnée sensible détectée."}), 200

    key = Fernet.generate_key()
    fernet = Fernet(key)

    img_enc = img.copy()
    zones_cipher = []

    for z in zones:
        x1, y1, x2, y2 = z["bbox"]
        roi = img_enc[y1:y2, x1:x2]
        if roi.size == 0:
            continue
        roi_bytes = roi.tobytes()
        roi_enc = fernet.encrypt(roi_bytes)
        img_enc[y1:y2, x1:x2] = np.random.randint(0, 256, roi.shape, dtype=np.uint8)
        zones_cipher.append({
            "bbox": z["bbox"],
            "label": z["label"],
            "cipher_roi": roi_enc.decode("utf-8"),
            "shape": roi.shape
        })

    # Save encrypted image with suffix
    encrypted_filename = f"{name}_encrypted{ext}"
    enc_path = os.path.join(save_dir, encrypted_filename)
    cv2.imwrite(enc_path, img_enc)

    zones_cipher_path = os.path.join(save_dir, "zones_cipher.json")
    with open(zones_cipher_path, "w") as f:
        json.dump(zones_cipher, f, indent=2)


    key_path = os.path.join(DATA_FOLDER, f"{name}_key.key")
    with open(key_path, "wb") as f:
        f.write(key)

    # Update global metadata
    update_global_metadata(name, status="encrypted", encrypted=True, flags=len(zones_cipher))

    return jsonify({
        "message": "Chiffrement des zones effectué (pixels chiffrés)",
        "folder": name,
        "zones_ciphered": len(zones_cipher),
        "encrypted_image": f"data_storage/{name}/{encrypted_filename}",
        "key_path": f"data_storage/{name}_key.key"
    })


@app.route("/decrypt", methods=["POST"])
def decrypt_image_api():
    """
    Expects multipart/form-data:
      - key: uploaded key file
      - image_name: name of folder (no extension)
    """
    if "key" not in request.files or "image_name" not in request.form:
        return jsonify({"error": "Clé et nom d'image requis"}), 400

    key_file = request.files["key"]
    name = request.form["image_name"]
    folder = os.path.join(DATA_FOLDER, name)

    if not os.path.isdir(folder):
        return jsonify({"error": "Image introuvable"}), 404

    # Load key from uploaded file
    key = key_file.read()
    fernet = Fernet(key)

    try:
        zones_path = os.path.join(folder, "zones_cipher.json")
        if not os.path.exists(zones_path):
            return jsonify({"error": f"zones_cipher.json not found in {folder}"}), 500

        zones_cipher = json.load(open(zones_path))

        encrypted_files = [f for f in os.listdir(folder) if "_encrypted" in f]
        if not encrypted_files:
            return jsonify({"error": f"No encrypted image found in {folder}"}), 500

        enc_file = encrypted_files[0]
        img_path = os.path.join(folder, enc_file)
        img = cv2.imread(img_path)
        if img is None:
            return jsonify({"error": f"Failed to load encrypted image at {img_path}"}), 500

        restored = []
        for z in zones_cipher:
            x1, y1, x2, y2 = z["bbox"]
            roi_enc = z["cipher_roi"].encode("utf-8")
            shape = tuple(z["shape"])  # e.g. (h, w, 3)
            try:
                roi_bytes = fernet.decrypt(roi_enc)
                roi_restored = np.frombuffer(roi_bytes, dtype=img.dtype).reshape(shape)
                img[y1:y2, x1:x2] = roi_restored
                restored.append({"bbox": z["bbox"], "label": z["label"]})
            except Exception as e:
                print(f"[Decrypt error] zone {z['bbox']}: {e}")
    except Exception as e:
        return jsonify({"error": f"Decryption failed: {str(e)}"}), 500


    out = os.path.join(folder, "restored.png")
    cv2.imwrite(out, img)

    return jsonify({
        "restored": f"data_storage/{name}/restored.png",
        "zones_restored": len(restored)
    })

@app.route("/preview", methods=["POST"])
def preview_detection_api():
    if "file" not in request.files:
        return jsonify({"error": "Aucun fichier envoyé"}), 400
    file = request.files["file"]
    if not is_image_file(file.filename):
        return jsonify({"error": "Fichier non image"}), 400
    name, ext = os.path.splitext(file.filename)
    tmp = os.path.join(DATA_FOLDER, f"tmp_preview{ext}")
    file.save(tmp)

    zones, img = detect_and_process_sensitive_data(
        tmp,
        conf_thresh=0.3,
        use_tesseract=request.form.get("use_tesseract", "false").lower() == "true"
    )

    os.remove(tmp)

    preview = img.copy()
    detected = []
    for z in zones:
        x1, y1, x2, y2 = z["bbox"]
        cv2.rectangle(preview, (x1, y1), (x2, y2), (0, 255, 0), 2)
        cv2.putText(
            preview,
            f"{z['label']}: {z['texte'][:20]}...",
            (x1, y1 - 10),
            cv2.FONT_HERSHEY_SIMPLEX,
            0.7,
            (0, 255, 0),
            2
        )
        detected.append({"bbox": z["bbox"], "label": z["label"], "texte": z["texte"]})
    preview_path = os.path.join(DATA_FOLDER, f"preview_{name}{ext}")
    cv2.imwrite(preview_path, preview)

    return jsonify({"preview_image": preview_path, "total_zones": len(zones)})

@app.route("/upload", methods=["POST"])
def upload_detection_api():
    if "file" not in request.files:
        return jsonify({"error": "Aucun fichier envoyé"}), 400
    file = request.files["file"]
    if not is_image_file(file.filename):
        return jsonify({"error": "Fichier non image"}), 400
    name, ext = os.path.splitext(file.filename)
    tmp = os.path.join(DATA_FOLDER, f"tmp_upload{ext}")
    file.save(tmp)

    zones, img = detect_and_process_sensitive_data(
        tmp,
        conf_thresh=0.3,
        use_tesseract=request.form.get("use_tesseract", "false").lower() == "true"
    )

    os.remove(tmp)

    simple = [
        {"bbox": z["bbox"], "label": z["label"], "texte": z["texte"], "confidence": z["score"]}
        for z in zones
    ]
    return jsonify({"zones": simple, "total_zones": len(simple)})

@app.route("/mask", methods=["POST"])
def mask_image_api():
    if "file" not in request.files:
        return jsonify({"error": "Aucun fichier envoyé"}), 400
    file = request.files["file"]
    if not is_image_file(file.filename):
        return jsonify({"error": "Fichier non image"}), 400

    name, ext = os.path.splitext(file.filename)
    save_dir = os.path.join(DATA_FOLDER, name)

    # Clean and recreate directory
    if os.path.exists(save_dir):
        shutil.rmtree(save_dir)
    os.makedirs(save_dir, exist_ok=True)

    # Save temporary file
    tmp = os.path.join(save_dir, f"tmp{ext}")
    file.save(tmp)

    # Detect sensitive zones
    zones, img = detect_and_process_sensitive_data(
        tmp,
        conf_thresh=0.3,
        use_tesseract=request.form.get("use_tesseract", "false").lower() == "true"
    )
    os.remove(tmp)

    # If no sensitive zones found
    if not zones:
        return jsonify({"message": "Aucune donnée sensible détectée."}), 200

    # Apply Gaussian blur to detected zones
    img_blur = img.copy()
    blurred_boxes = []
    for z in zones:
        x1, y1, x2, y2 = z["bbox"]
        roi = img_blur[y1:y2, x1:x2]
        if roi.size > 0:
            blurred = cv2.GaussianBlur(roi, (31, 31), 0)
            img_blur[y1:y2, x1:x2] = blurred
            blurred_boxes.append({"bbox": z["bbox"], "label": z["label"]})

    # Save masked file with _masked suffix
    masked_filename = f"{name}_masked{ext}"
    blur_path = os.path.join(save_dir, masked_filename)
    cv2.imwrite(blur_path, img_blur)

    # Save metadata for masked file
    metadata_path = os.path.join(save_dir, "metadata.json")
    with open(metadata_path, "w") as meta_f:
        json.dump({
            "status": "masked",
            "encrypted": False,
            "flags": len(zones)
        }, meta_f)

    # Update global metadata separately for masked version
    update_global_metadata(
        f"{name}_masked",      # use unique key for masked file
        status="masked",
        encrypted=False,
        flags=len(zones)
    )

    return jsonify({
        "message": "Blurring appliqué sur les zones sensibles",
        "folder": f"{name}_masked",
        "zones_masked": len(blurred_boxes),
        "masked_image": os.path.abspath(os.path.join("data_storage", name, masked_filename))
    })

# ---------------- FILE DETECTION & ENCRYPTION ROUTES ----------------

@app.route('/detectfiles', methods=['POST'])
def detect_files_api():
    if 'file' not in request.files:
        return jsonify({'error': 'Aucun fichier envoyé'}), 400

    file = request.files['file']
    ext = os.path.splitext(file.filename)[1].lower()
    temp_dir = tempfile.mkdtemp(prefix="detect_")
    temp_path = os.path.join(temp_dir, "input" + ext)
    file.save(temp_path)

    detected, *_ = auto_detect_and_process(temp_path)
    return jsonify({'detected': detected})


@app.route('/maskfiles', methods=['POST'])
def mask_files_api():
    """
    Process non-image files: mask sensitive data, save to DATA_FOLDER, update metadata,
    and prepare for Drive upload.
    """
    if 'file' not in request.files:
        return jsonify({'error': 'Aucun fichier envoyé'}), 400

    file = request.files['file']
    name, ext = os.path.splitext(file.filename)
    file_type = ext.lower().replace('.', '')

    # --- Create persistent folder under DATA_FOLDER (unique for masked) ---
    folder_name = f"{name}_masked"
    folder_path = os.path.join(DATA_FOLDER, folder_name)
    if os.path.exists(folder_path):
        shutil.rmtree(folder_path)
    os.makedirs(folder_path, exist_ok=True)

    # --- Save original file temporarily for processing ---
    temp_input_path = os.path.join(folder_path, f"input{ext}")
    file.save(temp_input_path)

    # --- Output masked file path ---
    masked_filename = f"{name}_masked{ext}"
    masked_path = os.path.join(folder_path, masked_filename)

    # --- Dispatch masking by file type ---
    if file_type == "csv":
        mask_csv_file(temp_input_path, masked_path)
    elif file_type == "docx":
        mask_docx_file(temp_input_path, masked_path)
    elif file_type == "txt":
        mask_txt_file(temp_input_path, masked_path)
    elif file_type == "xlsx":
        mask_xlsx_file(temp_input_path, masked_path)
    elif file_type == "pdf":
        blur_sensitive_pdf(temp_input_path, masked_path)
    else:
        return jsonify({'error': 'Format non supporté'}), 400

    if not os.path.exists(masked_path):
        return jsonify({'error': 'Anonymisation échouée'}), 500

    # --- Update metadata (masked) ---
    detected, *_ = auto_detect_and_process(temp_input_path)
    flags_count = len(detected.get("0", [])) if isinstance(detected, dict) else 0

    # --- Update metadata (masked) ---
    metadata_path = os.path.join(folder_path, "metadata.json")
    with open(metadata_path, "w") as meta_f:
        json.dump({
            "status": "masked",
            "encrypted": False,
            "flags": flags_count
        }, meta_f)

    update_global_metadata(
        folder_name,
        status="masked",
        encrypted=False,
        flags=flags_count
    )


    # --- Return masked file info (single file path, not folder) ---
    return jsonify({
        "message": "Masked file processed",
        "folder": folder_name,
        "masked_file": os.path.abspath(masked_path)
    })

@app.route('/encryptfiles', methods=['POST'])
def encrypt_files_api():
    """
    Encrypt non-image files, save to DATA_FOLDER, update metadata, and prepare for Drive upload.
    """
    if 'file' not in request.files:
        return jsonify({'error': 'Aucun fichier envoyé'}), 400

    file = request.files['file']
    name, ext = os.path.splitext(file.filename)

    # --- Create persistent folder under DATA_FOLDER ---
    folder_name = f"{name}_encrypted"
    folder_path = os.path.join(DATA_FOLDER, folder_name)
    if os.path.exists(folder_path):
        shutil.rmtree(folder_path)
    os.makedirs(folder_path, exist_ok=True)

    # --- Save file for detection & encryption ---
    input_path = os.path.join(folder_path, f"input{ext}")
    file.save(input_path)

    # --- Detect sensitive data for flag count ---
    detected_entities, *_ = auto_detect_and_process(input_path)
    flags_count = len(detected_entities.get("0", []))

    # --- Output encrypted file path ---
    encrypted_filename = f"{name}_encrypted{ext}"
    encrypted_path = os.path.join(folder_path, encrypted_filename)

    # --- Perform encryption ---
    encrypt_sensitive_data(input_path, encrypted_path)
    if not os.path.exists(encrypted_path):
        return jsonify({'error': 'Chiffrement échoué'}), 500

    # --- Generate TenSEAL context for decryption ---
    context_filename = "tenseal_context.ctx"
    context_path = os.path.join(folder_path, context_filename)
    if not os.path.exists(context_path):
        setup_context(context_path)

    # --- Save JSON metadata (flags + status) ---
    metadata_path = os.path.join(folder_path, "metadata.json")
    with open(metadata_path, "w") as meta_f:
        json.dump({
            "status": "encrypted",
            "encrypted": True,
            "flags": flags_count
        }, meta_f)

    # --- Also store flags in global metadata for dashboard tags ---
    update_global_metadata(
        folder_name,
        status="encrypted",
        encrypted=True,
        flags=flags_count
    )

    # --- Return RELATIVE paths so frontend can download ---
    return jsonify({
        "message": "File encrypted successfully",
        "folder": folder_name,
        "encrypted_file": f"data_storage/{folder_name}/{encrypted_filename}",
        "context_file": f"data_storage/{folder_name}/{context_filename}",
        "flags": flags_count
    })

@app.route('/decryptfiles', methods=['POST'])
def decrypt_files_api():
    """
    Expects multipart/form-data:
      - file: encrypted file
      - context: TenSEAL context file
      - metadata: encrypted_data.json (required for decryption)
    Returns:
      - Decrypted file
    """
    if 'file' not in request.files or 'context' not in request.files or 'metadata' not in request.files:
        return jsonify({'error': 'Encrypted file, context, and metadata required'}), 400

    file = request.files['file']
    context_file = request.files['context']
    meta_file = request.files['metadata']  # <-- NEW

    # Keep original file extension for decrypted output
    ext = os.path.splitext(file.filename)[1].lower()

    # Create a temporary directory for processing
    temp_dir = tempfile.mkdtemp(prefix="decrypt_")
    encrypted_path = os.path.join(temp_dir, "encrypted" + ext)
    decrypted_path = os.path.join(temp_dir, "decrypted" + ext)

    # Save uploaded files
    file.save(encrypted_path)
    ctx_path = os.path.join(temp_dir, "context.ctx")
    context_file.save(ctx_path)

    # Save metadata JSON alongside encrypted file
    meta_path = f"{encrypted_path}_encrypted_data.json"
    meta_file.save(meta_path)

    try:
        decrypt_document(encrypted_path, decrypted_path, ctx_path)
    except Exception as e:
        import traceback
        print("=== DECRYPT ERROR ===")
        print(traceback.format_exc())   # Full traceback in console
        return jsonify({'error': f'Déchiffrement échoué: {str(e)}'}), 500

    # Return decrypted file
    return send_file(
        decrypted_path,
        as_attachment=True,
        download_name=f"decrypted{ext}"
    )

# --- Serve keys for download ---
@app.route('/data_storage/<path:filename>')
@cross_origin(supports_credentials=True)
def serve_processed_file(filename):
    return send_from_directory(DATA_FOLDER, filename)

@app.route('/data_storage_keys/<path:filename>')
@cross_origin(supports_credentials=True)
def serve_keys_file(filename):
    return send_from_directory(DATA_FOLDER, filename)


if __name__ == "__main__":
    print("🔐 Serveur de chiffrement et masquage démarré")
    print("📝 Endpoints disponibles:")
    print("  - POST /encrypt  : Chiffrer une image")
    print("  - POST /decrypt  : Déchiffrer une image")
    print("  - POST /preview  : Prévisualiser détections")
    print("  - POST /upload   : Détection simple (zones)")
    print("  - POST /mask     : Masquer zones détectées")
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=True, host="0.0.0.0", port=port)   


