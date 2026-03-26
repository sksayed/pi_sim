TOPIC_PATTERN = "nodes/+/data"


def device_topic(device_id: str) -> str:
    return f"nodes/{device_id}/data"
