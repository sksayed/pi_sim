TOPIC_PATTERN = "nodes/+/data"
# Stage 2 publishes the re-encrypted envelope here. The cloud PC subscribes.
CLOUD_UPLINK_TOPIC = "cloud/uplink"


def device_topic(device_id: str) -> str:
    return f"nodes/{device_id}/data"
