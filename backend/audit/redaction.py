from urllib.parse import urlsplit


def redact_event(event: dict) -> dict:
    result = dict(event)
    try:
        url = urlsplit(result.get("target_url", ""))
        host = url.hostname or ""
        authority = f"[{host}]" if ":" in host else host
        if url.port:
            authority += f":{url.port}"
        result["target_url"] = f"{url.scheme}://{authority}" if host else "invalid-url"
    except ValueError:
        result["target_url"] = "invalid-url"
    result["request_summary"] = ""
    result["response_summary"] = None
    details = result.get("detection_details")
    result["detection_details"] = {"patterns": details.get("patterns", [])} if isinstance(details, dict) else None
    return result
