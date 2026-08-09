import { create } from 'zustand';

export interface WsMessage {
  type: string;
  data?: unknown;
  [key: string]: unknown;
}

type WsHandler = (msg: WsMessage) => void;

interface WsState {
  connected: boolean;
  lastMessage: WsMessage | null;
  connect: () => void;
  disconnect: () => void;
  /** 订阅指定消息类型（'*' 表示通配），返回取消订阅函数 */
  on: (type: string, handler: WsHandler) => () => void;
}

let ws: WebSocket | null = null;
let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
let heartbeatTimer: ReturnType<typeof setInterval> | null = null;
let shouldReconnect = true;
let retryDelay = 1000;

/** 消息类型 -> 订阅回调集合 */
const handlers = new Map<string, Set<WsHandler>>();

/** 指数退避重连：1s -> 2s -> 4s ... 上限 30s */
function scheduleReconnect() {
  if (!shouldReconnect || reconnectTimer) return;
  reconnectTimer = setTimeout(() => {
    reconnectTimer = null;
    useWsStore.getState().connect();
  }, retryDelay);
  retryDelay = Math.min(retryDelay * 2, 30000);
}

/** 心跳：每 30s 发送 {type:'ping'} 保活 */
function startHeartbeat() {
  stopHeartbeat();
  heartbeatTimer = setInterval(() => {
    if (ws && ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify({ type: 'ping' }));
    }
  }, 30000);
}

function stopHeartbeat() {
  if (heartbeatTimer) {
    clearInterval(heartbeatTimer);
    heartbeatTimer = null;
  }
}

/** 按消息类型派发 + 同时派发到 '*' 通配 */
function dispatch(msg: WsMessage) {
  handlers.get(msg.type)?.forEach((fn) => fn(msg));
  handlers.get('*')?.forEach((fn) => fn(msg));
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
      startHeartbeat();
    };

    ws.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data) as WsMessage;
        set({ lastMessage: msg });
        dispatch(msg);
      } catch (e) {
        console.error('[ws] 消息解析失败:', e);
      }
    };

    ws.onclose = () => {
      set({ connected: false });
      stopHeartbeat();
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
    stopHeartbeat();
    ws?.close();
    ws = null;
  },
  on: (type, handler) => {
    let list = handlers.get(type);
    if (!list) {
      list = new Set();
      handlers.set(type, list);
    }
    list.add(handler);
    return () => {
      list?.delete(handler);
      if (list?.size === 0) handlers.delete(type);
    };
  }
}));

/** 兼容按需调用（getState 的方法为稳定引用，可安全解构使用） */
export const wsClient = useWsStore.getState();
