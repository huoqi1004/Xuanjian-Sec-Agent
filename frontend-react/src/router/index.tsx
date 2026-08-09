import { createBrowserRouter, Navigate } from 'react-router-dom';
import type { ReactNode } from 'react';
import MainLayout from '@/layouts/MainLayout';
import AgentWorkbench from '@/pages/AgentWorkbench';
import Assistant from '@/pages/Assistant';
import Baseline from '@/pages/Baseline';
import Config from '@/pages/Config';
import Dashboard from '@/pages/Dashboard';
import Defense from '@/pages/Defense';
import Device from '@/pages/Device';
import Djpp from '@/pages/Djpp';
import Login from '@/pages/Login';
import Playbook from '@/pages/Playbook';
import Reports from '@/pages/Reports';
import Scan from '@/pages/Scan';
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
      { path: 'scan', element: <Scan /> },
      { path: 'baseline', element: <Baseline /> },
      { path: 'assistant', element: <Assistant /> },
      { path: 'defense', element: <Defense /> },
      { path: 'situational', element: <Situational /> },
      { path: 'agent', element: <AgentWorkbench /> },
      { path: 'device', element: <Device /> },
      { path: 'users', element: <Users /> },
      { path: 'virus', element: <Virus /> },
      { path: 'djpp', element: <Djpp /> },
      { path: 'playbook', element: <Playbook /> },
      { path: 'reports', element: <Reports /> },
      { path: 'config', element: <Config /> }
    ]
  },
  { path: '*', element: <Navigate to="/dashboard" replace /> }
]);

export default router;
