import type { WsMessage } from '@/types';

type WsHandler = (msg: WsMessage) => void;

/** WebSocket 封装：自动重连、心跳、事件订阅（对应后端 /ws/frontend 通道） */
class WsClient {
  private ws: WebSocket | null = null;
  private handlers = new Map<string, WsHandler[]>();
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private heartbeatTimer: ReturnType<typeof setInterval> | null = null;
  private shouldReconnect = true;
  private retryDelay = 3000;
  onStatusChange: ((connected: boolean) => void) | null = null;

  connect() {
    const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const url = `${proto}//${window.location.host}/ws/frontend`;
    this.shouldReconnect = true;

    try {
      this.ws = new WebSocket(url);
    } catch (e) {
      this.scheduleReconnect();
      return;
    }

    this.ws.onopen = () => {
      this.onStatusChange?.(true);
      this.startHeartbeat();
    };

    this.ws.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data) as WsMessage;
        const list = this.handlers.get(msg.type) || [];
        list.forEach((fn) => fn(msg));
        // 同时派发到通配 handler
        const wildcard = this.handlers.get('*') || [];
        wildcard.forEach((fn) => fn(msg));
      } catch (e) {
        console.error('[ws] 消息解析失败:', e);
      }
    };

    this.ws.onclose = () => {
      this.onStatusChange?.(false);
      this.stopHeartbeat();
      this.scheduleReconnect();
    };

    this.ws.onerror = () => {
      this.ws?.close();
    };
  }

  private scheduleReconnect() {
    if (!this.shouldReconnect || this.reconnectTimer) return;
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null;
      this.connect();
    }, this.retryDelay);
  }

  private startHeartbeat() {
    this.stopHeartbeat();
    this.heartbeatTimer = setInterval(() => {
      if (this.ws && this.ws.readyState === WebSocket.OPEN) {
        this.ws.send(JSON.stringify({ type: 'ping' }));
      }
    }, 30000);
  }

  private stopHeartbeat() {
    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer);
      this.heartbeatTimer = null;
    }
  }

  /** 订阅消息类型，返回取消订阅函数 */
  on(type: string, handler: WsHandler): () => void {
    const list = this.handlers.get(type) || [];
    list.push(handler);
    this.handlers.set(type, list);
    return () => {
      const cur = this.handlers.get(type) || [];
      this.handlers.set(
        type,
        cur.filter((fn) => fn !== handler)
      );
    };
  }

  disconnect() {
    this.shouldReconnect = false;
    this.stopHeartbeat();
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    this.ws?.close();
    this.ws = null;
  }
}

export const wsClient = new WsClient();
