import { createBrowserRouter, Navigate } from 'react-router-dom';
import type { ReactNode } from 'react';
import MainLayout from '@/layouts/MainLayout';
import Login from '@/pages/Login';
import { useUserStore } from '@/stores/user';

function RequireAuth({ children }: { children: ReactNode }) {
  const token = useUserStore((s) => s.token);
  if (!token) return <Navigate to="/login" replace />;
  return <>{children}</>;
}

/** 占位页：后续迭代替换为真实页面 */
const Placeholder = ({ title }: { title: string }) => (
  <div className="p-8 text-lg">该页面将在后续迭代迁移（{title}）</div>
);

export const router = createBrowserRouter([
  { path: '/login', element: <Login /> },
  {
    path: '/',
    element: (
      <RequireAuth>
        <MainLayout />
      </RequireAuth>
    ),
    children: [
      { index: true, element: <Navigate to="/dashboard" replace /> },
      { path: 'dashboard', element: <Placeholder title="安全概览" /> },
      { path: 'agent', element: <Placeholder title="Agent 工作台" /> }
    ]
  },
  { path: '*', element: <Navigate to="/dashboard" replace /> }
]);

export default router;
