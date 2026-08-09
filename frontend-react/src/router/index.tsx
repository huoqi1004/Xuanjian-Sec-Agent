import { createBrowserRouter, Navigate } from 'react-router-dom';
import type { ReactNode } from 'react';
import MainLayout from '@/layouts/MainLayout';
import AgentWorkbench from '@/pages/AgentWorkbench';
import Dashboard from '@/pages/Dashboard';
import Login from '@/pages/Login';
import Situational from '@/pages/Situational';
import { useUserStore } from '@/stores/user';

function RequireAuth({ children }: { children: ReactNode }) {
  const token = useUserStore((s) => s.token);
  if (!token) return <Navigate to="/login" replace />;
  return <>{children}</>;
}

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
      { path: 'dashboard', element: <Dashboard /> },
      { path: 'situational', element: <Situational /> },
      { path: 'agent', element: <AgentWorkbench /> }
    ]
  },
  { path: '*', element: <Navigate to="/dashboard" replace /> }
]);

export default router;
