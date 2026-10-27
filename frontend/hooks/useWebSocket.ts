"use client";

import { useEffect, useEffectEvent, useState } from "react";
import type { AuditEvent, WebSocketMessage } from "@/lib/types";

const WS_URL = process.env.NEXT_PUBLIC_WS_URL || "ws://localhost:8000/api/ws";

export function useWebSocket(apiKey: string, onEvent: (event: AuditEvent) => void, onError: (message: string, unauthorized: boolean) => void) {
  const [connectedKey, setConnectedKey] = useState("");
  const handleEvent = useEffectEvent(onEvent);
  const handleError = useEffectEvent(onError);

  useEffect(() => {
    if (!apiKey) return;
    let active = true;
    let ws: WebSocket;
    let retry: ReturnType<typeof setTimeout> | undefined;

    function connect() {
      ws = new WebSocket(WS_URL);
      ws.onopen = () => {
        if (active) ws.send(JSON.stringify({ token: apiKey }));
      };
      ws.onmessage = (event) => {
        if (!active) return;
        try {
          const msg: WebSocketMessage = JSON.parse(event.data);
          if (msg.type === "authenticated") {
            setConnectedKey(apiKey);
            handleError("", false);
          }
          if (msg.type === "new_event") handleEvent(msg.payload as AuditEvent);
        } catch {
          handleError("ClawGuard sent an unreadable live update", false);
        }
      };
      ws.onclose = (event) => {
        if (!active) return;
        setConnectedKey("");
        if (event.code === 1008) {
          handleError("Admin key rejected. Enter a valid key to reconnect.", true);
          return;
        }
        handleError("Live updates disconnected. Reconnecting…", false);
        retry = setTimeout(connect, 2000);
      };
      ws.onerror = () => ws.close();
    }
    connect();
    return () => {
      active = false;
      clearTimeout(retry);
      ws.close();
      setConnectedKey("");
    };
  }, [apiKey]);

  return { connected: Boolean(apiKey) && connectedKey === apiKey };
}
