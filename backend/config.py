# backend/config.py
import os
from dotenv import load_dotenv

load_dotenv()

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
BREVO_API_KEY = os.getenv("BREVO_API_KEY")
BREVO_SENDER = os.getenv("BREVO_SENDER")
BREVO_RECEIVER = os.getenv("BREVO_RECEIVER")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
LOG_DIR = os.path.join("logs")


#use from config import GEMINI_API_KEY, BREVO_API_KEY, BREVO_SENDER, BREVO_RECEIVER, VIRUSTOTAL_API_KEY, LOG_DIR
