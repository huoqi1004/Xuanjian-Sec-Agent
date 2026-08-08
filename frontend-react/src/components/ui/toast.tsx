import { useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';

export type ToastVariant = 'default' | 'success' | 'error' | 'warning';

export interface ToastOptions {
  title: string;
  description?: string;
  variant?: ToastVariant;
}

interface ToastItem extends ToastOptions {
  id: number;
}

let toasts: ToastItem[] = [];
const subscribers = new Set<() => void>();
let nextId = 1;

function emit() {
  subscribers.forEach((fn) => fn());
}

function dismiss(id: number) {
  toasts = toasts.filter((t) => t.id !== id);
  emit();
}

/** window 级单例 toast：自动 3s 消失 */
export function toast(options: ToastOptions) {
  const id = nextId++;
  toasts = [...toasts, { id, ...options }];
  emit();
  setTimeout(() => dismiss(id), 3000);
}

const variantClasses: Record<ToastVariant, string> = {
  default: 'border-gray-200 bg-white text-gray-900',
  success: 'border-green-200 bg-green-50 text-green-800',
  error: 'border-red-200 bg-red-50 text-red-800',
  warning: 'border-amber-200 bg-amber-50 text-amber-800'
};

function ToastViewport() {
  const [, forceUpdate] = useState(0);
  useEffect(() => {
    const fn = () => forceUpdate((n) => n + 1);
    subscribers.add(fn);
    return () => {
      subscribers.delete(fn);
    };
  }, []);
  return (
    <div className="pointer-events-none fixed right-4 top-4 z-[9999] flex w-80 flex-col gap-2">
      {toasts.map((t) => (
        <div
          key={t.id}
          className={`pointer-events-auto rounded-md border p-3 shadow-lg ${variantClasses[t.variant ?? 'default']}`}
        >
          <div className="text-sm font-semibold">{t.title}</div>
          {t.description && <div className="mt-1 text-xs opacity-80">{t.description}</div>}
        </div>
      ))}
    </div>
  );
}

let mounted = false;
function ensureMounted() {
  if (mounted) return;
  mounted = true;
  const el = document.createElement('div');
  document.body.appendChild(el);
  createRoot(el).render(<ToastViewport />);
}

ensureMounted();
