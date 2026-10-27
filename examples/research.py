"""Fetch one approved source through a running ClawGuard gateway."""
import sys

from clawguard import ClawGuardClient, ClawGuardError


def main() -> int:
    url = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"
    client = ClawGuardClient(agent_id="research-agent", timeout=30)
    try:
        result = client.check_sync(
            url, tool_name="web_fetch", headers={"User-Agent": "ClawGuardResearch/0.2"},
            raise_on_block=True,
        )
    except ClawGuardError as error:
        print(f"Research request failed: {error}", file=sys.stderr)
        return 1
    if not 200 <= result.status_code < 300:
        print(f"Source returned HTTP {result.status_code}", file=sys.stderr)
        return 1
    print(result.body)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
