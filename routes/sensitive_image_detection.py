
import os
import cv2
import base64
import numpy as np
from ultralytics import YOLO
from cryptography.fernet import Fernet
from easyocr import Reader
import json

# ========== CONFIG ==========
MODEL_WEIGHTS = "best.pt"

KEY_FILE = "secret.key"
DATA_FOLDER = "data_storage"
IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png", ".bmp", ".gif"}

os.makedirs(DATA_FOLDER, exist_ok=True)

# ========== INIT MODELS ==========
model = YOLO(MODEL_WEIGHTS)
reader = Reader(['en', 'fr'])

# ========== KEY MANAGEMENT ==========
def load_or_generate_key():
    if os.path.exists(KEY_FILE):
        return open(KEY_FILE, "rb").read()
    key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as f:
        f.write(key)
    return key
def encrypt_roi(roi, fernet):
    ok, buffer = cv2.imencode('.png', roi)
    roi_bytes = buffer.tobytes()
    encrypted_bytes = fernet.encrypt(roi_bytes)
    encrypted_b64 = base64.b64encode(encrypted_bytes).decode("utf-8")
    return encrypted_b64

def decrypt_roi(encrypted_b64, fernet):
    encrypted_bytes = base64.b64decode(encrypted_b64)
    roi_bytes = fernet.decrypt(encrypted_bytes)
    roi_arr = np.frombuffer(roi_bytes, np.uint8)
    roi_img = cv2.imdecode(roi_arr, cv2.IMREAD_COLOR)
    return roi_img

def encrypt_text(text: str, key: bytes) -> str:
    f = Fernet(key)
    ct = f.encrypt(text.encode("utf-8"))
    return base64.b64encode(ct).decode("utf-8")

def decrypt_text(ct_b64: str, key: bytes) -> str:
    f = Fernet(key)
    ct = base64.b64decode(ct_b64)
    return f.decrypt(ct).decode("utf-8")

def mask_sensitive_zones(img, zones):
    m = img.copy()
    for z in zones:
        x1, y1, x2, y2 = z["bbox"]
        cv2.rectangle(m, (x1, y1), (x2, y2), (128, 128, 128), thickness=-1)
    return m

# ========== OCR & STYLE HELPERS ==========
def extract_text_with_ocr(roi, use_tesseract=False):
    import pytesseract
    if use_tesseract:
        data = pytesseract.image_to_data(roi, output_type=pytesseract.Output.DICT)
        words, parts = [], []
        for i in range(len(data['text'])):
            if int(data['conf'][i]) > 30:
                x, y, w, h = data['left'][i], data['top'][i], data['width'][i], data['height'][i]
                wd = data['text'][i].strip()
                if wd:
                    words.append({'text': wd, 'bbox': (x, y, x+w, y+h), 'conf': data['conf'][i]})
                    parts.append(wd)
        return " ".join(parts), words
    else:
        ocr_results = reader.readtext(roi, detail=1)
        words, parts = [], []
        for pts, txt, conf in ocr_results:
            if conf > 0.3:
                xs = [p[0] for p in pts]
                ys = [p[1] for p in pts]
                x1, y1 = int(min(xs)), int(min(ys))
                x2, y2 = int(max(xs)), int(max(ys))
                words.append({'text': txt, 'bbox': (x1, y1, x2, y2), 'conf': conf})
                parts.append(txt)
        return " ".join(parts), words

def estimate_font_properties(roi, words, full_text):
    if not words:
        return 1.0, (0, 0, 0)
    avg_h = np.mean([w['bbox'][3] - w['bbox'][1] for w in words])
    (_, th), _ = cv2.getTextSize(full_text or "Test", cv2.FONT_HERSHEY_SIMPLEX, 1.0, 2)
    scale = (avg_h * 0.8) / th if th > 0 else 1.0
    gray = cv2.cvtColor(roi, cv2.COLOR_BGR2GRAY)
    _, binar = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
    white = np.sum(binar == 255)
    black = np.sum(binar == 0)
    color = (255, 255, 255) if white > black else (0, 0, 0)
    return scale, color

def fit_text_in_bbox(text, bw, bh, max_scale=3.0, min_scale=0.2):
    scale = max_scale
    while scale >= min_scale:
        (tw, th), _ = cv2.getTextSize(text, cv2.FONT_HERSHEY_SIMPLEX, scale, 2)
        if tw <= bw * 0.9 and th <= bh * 0.7:
            return scale
        scale -= 0.05
    return min_scale

def get_text_position_in_bbox(bbox, text, scale):
    x1, y1, x2, y2 = bbox
    bw, bh = x2 - x1, y2 - y1
    (tw, th), _ = cv2.getTextSize(text, cv2.FONT_HERSHEY_SIMPLEX, scale, 2)
    tx = x1 + (bw - tw) // 2
    ty = y1 + (bh + th) // 2
    return (tx, ty)

# ========== DETECTION PRINCIPALE ==========
def detect_and_process_sensitive_data(image_path, conf_thresh=0.3, use_tesseract=False):
    """
    Détecte les zones sensibles dans l'image et retourne
    - une liste de zones : [{bbox, label, score, texte, words, font_scale, color}]
    - l'image chargée (cv2)
    """
    img = cv2.imread(image_path)
    if img is None:
        raise ValueError(f"Image introuvable : {image_path}")

    results = model.predict(source=image_path, conf=conf_thresh)
    zones = []

    for result in results:
        boxes = result.boxes.xyxy.cpu().numpy()
        classes = result.boxes.cls.cpu().numpy()
        scores = result.boxes.conf.cpu().numpy()
        names = result.names

        for box, cls_id, score in zip(boxes, classes, scores):
            x1, y1, x2, y2 = map(int, box)
            label = names[int(cls_id)]
            roi = img[y1:y2, x1:x2]
            if roi.size == 0:
                # Pour éviter les découpes vides
                texte, words, scale, color = "", [], 1.0, (255, 255, 255)
            else:
                texte, words = extract_text_with_ocr(roi, use_tesseract)
                scale, color = estimate_font_properties(roi, words, texte)

            zones.append({
                "bbox": [x1, y1, x2, y2],
                "label": label,
                "score": float(score),
                "texte": texte,
                "words": words,
                "font_scale": scale,
                "color": color
            })

    return zones, img

def is_image_file(fname):
    return os.path.splitext(fname)[1].lower() in IMAGE_EXTENSIONS