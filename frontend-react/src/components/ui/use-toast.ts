import { toast } from './toast';
import type { ToastOptions } from './toast';

export interface ToastFn {
  (options: ToastOptions): void;
}

/** 返回全局单例 toast 方法：{ toast: ({title, description?, variant?}) => void } */
export function useToast(): { toast: ToastFn } {
  return { toast };
}

export type { ToastOptions };
