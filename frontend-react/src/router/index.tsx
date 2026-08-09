import { createBrowserRouter, Navigate } from 'react-router-dom';
import type { ReactNode } from 'react';
import MainLayout from '@/layouts/MainLayout';
import AgentWorkbench from '@/pages/AgentWorkbench';
import Assistant from '@/pages/Assistant';
import Dashboard from '@/pages/Dashboard';
import Defense from '@/pages/Defense';
import Device from '@/pages/Device';
import Djpp from '@/pages/Djpp';
import Login from '@/pages/Login';
import Situational from '@/pages/Situational';
import Users from '@/pages/Users';
import Virus from '@/pages/Virus';
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
      { path: 'assistant', element: <Assistant /> },
      { path: 'defense', element: <Defense /> },
      { path: 'situational', element: <Situational /> },
      { path: 'agent', element: <AgentWorkbench /> },
      { path: 'device', element: <Device /> },
      { path: 'users', element: <Users /> },
      { path: 'virus', element: <Virus /> },
      { path: 'djpp', element: <Djpp /> }
    ]
  },
  { path: '*', element: <Navigate to="/dashboard" replace /> }
]);

export default router;
