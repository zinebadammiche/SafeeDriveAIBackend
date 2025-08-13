FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Dépendances système
RUN apt-get update && apt-get install -y --no-install-recommends \
    git cmake build-essential libssl-dev python3-dev libgl1 libglib2.0-0 \
 && rm -rf /var/lib/apt/lists/*

# Installer PyTorch CPU-only en premier
RUN pip install --upgrade pip \
 && pip install --index-url https://download.pytorch.org/whl/cpu \
    torch==2.4.1 torchvision==0.19.1 torchaudio==2.4.1

# Copier et installer les autres dépendances
COPY requirements.txt /app/
RUN pip install --prefer-binary -r requirements.txt \
 && pip cache purge || true

# Copier le code applicatif
COPY . /app/

EXPOSE 5000

CMD ["python", "app.py"]
