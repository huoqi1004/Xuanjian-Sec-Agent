import axios, { type AxiosInstance, type AxiosRequestConfig, type AxiosError } from 'axios';
import { toast } from '@/components/ui/toast';
import { useUserStore } from '@/stores/user';

/** 后端统一响应格式 */
export interface ApiResponse<T = unknown> {
  code: number;
  message: string;
  data: T;
}

// 消息防抖，避免错误提示刷屏
const messageDebounce = new Map<string, number>();
function showMessage(type: 'success' | 'error' | 'warning', msg: string) {
  const key = `${type}:${msg}`;
  const now = Date.now();
  const last = messageDebounce.get(key) || 0;
  if (now - last < 3000) return;
  messageDebounce.set(key, now);
  toast({ title: msg, variant: type === 'success' ? 'success' : type === 'warning' ? 'warning' : 'error' });
}

const http: AxiosInstance = axios.create({
  baseURL: '/api',
  timeout: 30000,
  headers: { 'Content-Type': 'application/json' }
});

http.interceptors.request.use((config) => {
  const token = useUserStore.getState().token;
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

http.interceptors.response.use(
  (response) => response,
  (error: AxiosError<{ message?: string }>) => {
    if (error.response) {
      const status = error.response.status;
      if (status === 401) {
        useUserStore.getState().logout(false);
        window.location.href = '/login';
      } else if (status === 403) {
        showMessage('error', '权限不足，无法执行此操作');
      } else if (status === 429) {
        showMessage('warning', '操作过于频繁，请稍后再试');
      } else if (status >= 500) {
        showMessage('error', '服务器内部错误，请稍后重试');
      } else if (status === 400) {
        showMessage('error', error.response.data?.message || '请求参数错误');
      }
    } else if (error.code === 'ECONNABORTED') {
      showMessage('error', '请求超时，请检查网络连接');
    } else {
      showMessage('error', '网络连接失败，请检查网络');
    }
    return Promise.reject(error);
  }
);

/** 通用请求：返回完整响应体 { code, message, data }，与后端统一响应格式一致 */
export async function request<T = unknown>(config: AxiosRequestConfig): Promise<ApiResponse<T>> {
  const resp = await http.request<ApiResponse<T>>(config);
  return resp.data;
}

/** 业务层封装：成功时直接返回 data，失败时抛错 */
export async function requestData<T = unknown>(config: AxiosRequestConfig): Promise<T> {
  const resp = await http.request<ApiResponse<T>>(config);
  if (resp.data.code === 0) {
    return resp.data.data;
  }
  showMessage('error', resp.data.message || '操作失败');
  throw new Error(resp.data.message || '操作失败');
}

export default http;
