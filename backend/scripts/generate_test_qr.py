"""
Generate sample QR images for non-URL payloads (WiFi/SMS/UPI) to verify
risk messaging and logging in the QR detector.

Outputs PNG files under dashboard/static/images/tests/.
"""

import os
from io import BytesIO
from PIL import Image
import qrcode

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
OUT_DIR = os.path.join(BASE_DIR, "dashboard", "static", "images", "tests")
os.makedirs(OUT_DIR, exist_ok=True)

TEST_PAYLOADS = {
    "wifi_evil_twin": "WIFI:T:WPA;S:EvilTwinPublic;P:freewifi123;;",
    "sms_pay_now": "sms:+18005552345?body=PAY_NOW",
    "upi_scam": "upi://pay?pa=scam@ybl&am=10000",
}


def make_qr(data: str, filename: str):
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=10,
        border=4,
    )
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    out_path = os.path.join(OUT_DIR, filename)
    img.save(out_path)
    return out_path


def main():
    outputs = []
    for name, payload in TEST_PAYLOADS.items():
        fname = f"{name}.png"
        path = make_qr(payload, fname)
        outputs.append(path)
    print("Generated:")
    for p in outputs:
        print(" -", p)


if __name__ == "__main__":
    main()
