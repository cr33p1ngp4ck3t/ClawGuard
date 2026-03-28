"""
Attack demo runner. Fires all scenarios against ClawGuard.
Run: python -m demo.attacker
"""
from __future__ import annotations

import asyncio
import sys

import httpx

from demo.scenarios import SCENARIOS

PROXY_URL = "http://localhost:8000/proxy"


async def run_demo():
    print("\n" + "=" * 70)
    print("  ClawGuard Attack Demo")
    print("  Firing 3 attack scenarios against the proxy...")
    print("=" * 70)

    async with httpx.AsyncClient(timeout=10.0) as client:
        for i, scenario in enumerate(SCENARIOS, 1):
            print(f"\n{'-' * 60}")
            print(f"  ATTACK #{i}: {scenario['name']}")
            print(f"  {scenario['description']}")
            print(f"{'-' * 60}")

            try:
                response = await client.post(
                    PROXY_URL,
                    json=scenario["request"],
                )
                data = response.json()
                blocked = data.get("blocked", False)
                risk = data.get("risk_level", "unknown")
                threats = data.get("threats_detected", [])
                policy = data.get("policy_rule")

                status = "BLOCKED" if blocked else "ALLOWED"
                icon = "[X]" if blocked else "[!]"

                print(f"\n  {icon} Result: {status}")
                print(f"      Risk Level: {risk}")
                if threats:
                    print(f"      Threats: {', '.join(threats)}")
                if policy:
                    print(f"      Policy Rule: {policy}")
                print(f"      HTTP Status: {response.status_code}")

            except httpx.ConnectError:
                print("\n  [!] ERROR: Cannot connect to ClawGuard at", PROXY_URL)
                print("      Make sure the backend is running: uvicorn main:app")
                sys.exit(1)
            except Exception as e:
                print(f"\n  [!] ERROR: {e}")

    print(f"\n{'=' * 70}")
    print("  Demo complete. Check the dashboard for real-time results.")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    asyncio.run(run_demo())
