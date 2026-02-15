"""
Sound Alert Service - Plays audio alerts for threats
Local mode only - disabled by default for production/Docker
"""
import os
import logging
import time
import threading

# Cooldown timer for alert sound
last_alert_time = 0

# Try to import pygame (optional dependency)
try:
    import pygame
    pygame.mixer.init()
    _pygame_ok = True
except Exception as e:
    logging.warning(f"Pygame audio init failed or not available: {e}")
    _pygame_ok = False

# Production safety: disable by default
ENABLE_SOUND_ALERTS = os.getenv("ENABLE_SOUND_ALERTS", "false").lower() in ("true", "1", "yes")

def play_alert_sound():
    """
    Play alert sound with cooldown (5 seconds)
    Runs in background thread to avoid blocking
    """
    global last_alert_time
    current_time = time.time()
    
    # Cooldown check
    if current_time - last_alert_time < 5:
        return
    last_alert_time = current_time

    # Check if enabled
    if not ENABLE_SOUND_ALERTS:
        logging.debug("Sound alerts disabled (set ENABLE_SOUND_ALERTS=true to enable)")
        return
    
    if not _pygame_ok:
        logging.info("Skipping sound — pygame not available")
        return

    def _sound():
        try:
            pygame.mixer.music.load("alert_sound.mp3")
            pygame.mixer.music.play()
            pygame.time.delay(4000)
            pygame.mixer.music.stop()
        except Exception as e:
            logging.error(f"play_alert_sound error: {e}")

    threading.Thread(target=_sound, daemon=True).start()
