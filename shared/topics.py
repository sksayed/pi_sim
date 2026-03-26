import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv(dotenv_path=Path(__file__).resolve().parents[1] / ".env")

NETWORK_SSID = os.getenv("NETWORK_SSID", "YourHotspotSSID")
MQTT_TOPIC   = "pi/sensor/data"
