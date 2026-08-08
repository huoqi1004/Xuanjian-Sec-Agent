import { create } from 'zustand';

export interface WsMessage {
  type: string;
  data?: unknown;
  [key: string]: unknown;
}

interface WsState {
  connected: boolean;
  lastMessage: WsMessage | null;
  connect: () => void;
  disconnect: () => void;
}

let ws: WebSocket | null = null;
let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
let shouldReconnect = true;
let retryDelay = 1000;

/** 指数退避重连：1s -> 2s -> 4s ... 上限 30s */
function scheduleReconnect() {
  if (!shouldReconnect || reconnectTimer) return;
  reconnectTimer = setTimeout(() => {
    reconnectTimer = null;
    useWsStore.getState().connect();
  }, retryDelay);
  retryDelay = Math.min(retryDelay * 2, 30000);
}

/** WebSocket 封装（对应后端 /ws/frontend 通道） */
export const useWsStore = create<WsState>((set) => ({
  connected: false,
  lastMessage: null,
  connect: () => {
    const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const url = `${proto}//${window.location.host}/ws/frontend`;
    shouldReconnect = true;
    retryDelay = 1000;

    try {
      ws = new WebSocket(url);
    } catch (e) {
      scheduleReconnect();
      return;
    }

    ws.onopen = () => {
      set({ connected: true });
      retryDelay = 1000;
    };

    ws.onmessage = (event) => {
      try {
        set({ lastMessage: JSON.parse(event.data) as WsMessage });
      } catch (e) {
        console.error('[ws] 消息解析失败:', e);
      }
    };

    ws.onclose = () => {
      set({ connected: false });
      scheduleReconnect();
    };

    ws.onerror = () => {
      ws?.close();
    };
  },
  disconnect: () => {
    shouldReconnect = false;
    if (reconnectTimer) {
      clearTimeout(reconnectTimer);
      reconnectTimer = null;
    }
    ws?.close();
    ws = null;
  }
}));
