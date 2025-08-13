# SafeDrive AI – Intelligent & Secure Cloud Gateway

An advanced research and engineering project delivering a modern full-stack application for AI-driven file scanning and secure cloud storage integration. Designed with a strong focus on privacy protection, the system leverages React 18 + TypeScript for a high-performance, user-centric frontend and Flask (Python) for a robust, scalable backend. Styled with Tailwind CSS and seamlessly integrated with Google Drive, the solution combines cutting-edge AI, cryptography, and cloud deployment practices, culminating in a production-ready environment deployed via Docker on AWS EC2.

---

## 👥 Authors & Supervision

- **Authors**: Zineb Saraoui, Zineb Adammiche  
- **Supervisor**: Prof. Yann BEN MAISSA  
- **Institution**: National Institute of Posts and Telecommunications (INPT)

---

## 🌐 Live Deployment

- **Frontend (Vercel):** https://safe-drive-ai-frontend-mq6j.vercel.app  
- **Backend (EC2 / sslip.io):** https://13-39-110-169.sslip.io

> **Note:** The application communicates over HTTPS only. Ensure CORS settings on the backend include the frontend domain above.

---

## 🚀 Features

- **Google OAuth Authentication** – Secure sign-in with Google accounts
- **AI-Powered File Scanning** – Detection of sensitive data in images (PNG, JPG, JPEG) and documents (PDF, DOCX, XLSX, TXT, CSV)
- **Masking & Redaction** – Automatically blur sensitive visual areas in images and redact sensitive text in documents
- **Encryption** – Protect files using AES, RSA, or CKKS homomorphic encryption depending on file type
- **Decryption** – Securely restore encrypted files for authorized users
- **Drag & Drop Upload** – Intuitive file upload interface
- **Real-time Progress Tracking** – Visual feedback during file processing
- **File Management Dashboard** – Grid and list views for managing uploaded files
- **Flagged & Safe File Views** – Easily filter and review uploaded content
- **Dark/Light Mode** – Theme toggle
- **AI Insights Panel** – Detection results, bounding boxes, confidence scores, and recommendations
- **Secure Cloud Integration** – Safe upload and retrieval via Google Drive

---

## 📩 Access to the Service (Limited Testing Phase)

SafeDrive AI is currently in a **restricted access phase** due to Google OAuth verification requirements for Google Drive API integration. This process can take several weeks to months. Until verification is complete, only **registered test users** can use the service.

If you would like to try SafeDrive AI during this phase:

1. Send an email request to one of the following addresses:  
   - 📧 zinebadammiche03@gmail.com  
   - 📧 zinebsaraoui11@gmail.com
2. Include in your email:  
   - Your **Google account email** (the one you’ll use to log in)  
   - A short note that you’d like to join the tester list
3. Once we add you as a tester, access the service here:  
   👉 **Live Demo**: https://safe-drive-ai-frontend-mq6j.vercel.app

---

## 🛠️ Tech Stack

### **Frontend**
- **Framework**: React 18 + TypeScript
- **Build Tool**: Vite
- **Styling**: Tailwind CSS + shadcn/ui + Radix UI
- **Charts**: Recharts
- **Icons**: Lucide React
- **State Management**: useState, useEffect
- **API Communication**: Axios (RESTful API with credentials)

### **Backend**
- **Framework**: Flask (Python)
- **Security**: Google OAuth2, CORS, CSRF protection
- **AI Models**:  
  - **YOLOv8** for object detection in images  
  - **EasyOCR** for text extraction from images  
  - **Presidio + spaCy** for NLP-based sensitive data detection
- **Encryption**:  
  - **AES + RSA hybrid** for documents  
  - **CKKS homomorphic encryption (TenSEAL)** for images
- **Cloud Integration**: Google Drive API
- **File Handling**: Secure temporary storage, automatic cleanup
- **Async/Cache (optional)**: Redis (for task state, rate limiting, or caching)

---

## ⚙️ Configuration

Create a `.env` file **for the backend** (values are examples—replace with your own):

```env
# Flask
FLASK_SECRET_KEY=your-secret-key
FLASK_ENV=production

# CORS / CSRF
ALLOWED_ORIGINS=https://safe-drive-ai-frontend-mq6j.vercel.app
SESSION_COOKIE_SECURE=true
SESSION_COOKIE_SAMESITE=None

# Google OAuth2
GOOGLE_CLIENT_ID=your-google-oauth-client-id
GOOGLE_CLIENT_SECRET=your-google-oauth-client-secret
GOOGLE_REDIRECT_URI=https://13-39-110-169.sslip.io/auth/callback

# API
API_BASE_URL=https://13-39-110-169.sslip.io

 


Frontend .env file (Vite)

VITE_API_BASE=https://13-39-110-169.sslip.io
VITE_GOOGLE_CLIENT_ID=your-google-oauth-client-id
No localhost: This deployment uses the public Vercel frontend and sslip.io backend domains exclusively.


🐳 Containerization
📄 Dockerfile (backend)
 
# Use an official Python runtime as a base image
FROM python:3.11-slim

# Set environment variables for Python
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Set working directory inside the container
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    libgl1 \
    libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for caching
COPY requirements.txt /app/

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the backend source code
COPY . /app/

# Expose Flask port
EXPOSE 5000

# Start the Flask app
CMD ["flask", "run", "--host=0.0.0.0", "--port=5000"]
📄 docker-compose.yml
yaml
Copy
Edit
version: "3.9"

services:
  backend:
    build: .
    container_name: safedrive-backend
    restart: always
    ports:
      - "5000:5000"
    env_file:
      - .env
    volumes:
      - .:/app
    depends_on:
      - redis
    networks:
      - safedrive-network

  redis:
    image: redis:7-alpine
    container_name: safedrive-redis
    restart: always
    ports:
      - "6379:6379"
    networks:
      - safedrive-network

networks:
  safedrive-network:
    driver: bridge
Build & Run (backend  )

 
docker compose up --build -d
The backend will be available inside the Docker network as http://backend:5000, and publicly (if published) at https://13-39-110-169.sslip.io.


🔧 Local Development (optional)
Recommended only for contributors. Production uses the public domains above.

 
# Clone
git clone https://github.com/zinebadammiche/SafeeDriveAIBackend
git clone https://github.com/zinebadammiche/SafeeDriveAIBFrontend


# Backend (virtual env)
cd SafeeDriveAIBackend


python -m venv venv
source venv/bin/activate        # Linux/Mac
# venv\Scripts\activate        # Windows PowerShell
pip install -r requirements.txt

# Frontend
cd SafeeDriveAIBFrontend

npm install
npm run dev
Configure .env files as shown in Configuration, pointing to the public backend URL (https://13-39-110-169.sslip.io).

📜 Available Scripts
Frontend
npm run dev – Start development server (Vite)

npm run build – Build for production

npm run preview – Preview production build

 

Backend
python app.py 

## 🐳 Pull Backend Image from Docker Hub

The backend image is available on Docker Hub and can be pulled directly without building locally:

```bash
docker pull zinebadammiche/safedriveaibackend:latest

🔒 Security Features
OAuth-based authentication (Google)

Local file scanning before cloud upload

Multiple encryption schemes (AES, RSA, CKKS)

Masking of sensitive visual/textual content

File integrity verification

Secure Google Drive integration with access control

HTTPS-only communication between frontend and backend

☁️ Hosting
Frontend: Vercel

Backend: AWS EC2 (sslip.io DNS) or any container host

Storage: Google Drive API




🧪 Health Checks & Troubleshooting
Verify CORS: backend must allow origin https://safe-drive-ai-frontend-mq6j.vercel.app and include Access-Control-Allow-Credentials: true.

Ensure cookies are set with Secure and SameSite=None for cross-site OAuth flows.

For Redis-backed features, confirm REDIS_URL is reachable from the backend container.

Confirm Google OAuth test users are whitelisted in Google Cloud Console.


📄 License
This project is for academic and research purposes. Licensing terms can be updated as the project evolves.
