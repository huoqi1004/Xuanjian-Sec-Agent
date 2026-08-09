import { useEffect } from 'react';
import { NavLink, Outlet, useLocation } from 'react-router-dom';
import { useUserStore } from '@/stores/user';
import { useWsStore } from '@/stores/ws';

const menuItems = [
  { path: '/dashboard', title: '安全概览' },
  { path: '/scan', title: '网络扫描' },
  { path: '/baseline', title: '基线排查' },
  { path: '/virus', title: '病毒查杀' },
  { path: '/djpp', title: '等保测评' },
  { path: '/assistant', title: 'AI 助手' },
  { path: '/agent', title: 'Agent 工作台' },
  { path: '/situational', title: '态势感知' },
  { path: '/defense', title: '自动化防御' },
  { path: '/device', title: '边缘设备' },
  { path: '/users', title: '用户管理' },
  { path: '/playbook', title: 'SOAR 编排' },
  { path: '/config', title: '系统配置' },
  { path: '/reports', title: '报告管理' }
];

export default function MainLayout() {
  const user = useUserStore((s) => s.user);
  const logout = useUserStore((s) => s.logout);
  const connected = useWsStore((s) => s.connected);
  const connect = useWsStore((s) => s.connect);
  const location = useLocation();

  useEffect(() => {
    connect();
    return () => {
      useWsStore.getState().disconnect();
    };
  }, [connect]);

  const currentTitle = menuItems.find((item) => item.path === location.pathname)?.title || '玄鉴安全智能体';

  return (
    <div className="flex h-screen overflow-hidden bg-gray-100">
      {/* 侧边导航 */}
      <aside className="flex w-[220px] shrink-0 flex-col bg-gray-900 text-gray-300">
        <div className="flex items-center gap-2 border-b border-gray-800 px-4 py-4">
          <div className="h-8 w-8 shrink-0 rounded-full bg-gradient-to-br from-cyan-400 to-purple-500" />
          <span className="text-sm font-semibold text-white">玄鉴安全智能体</span>
        </div>
        <nav className="flex-1 overflow-y-auto px-2 py-3">
          {menuItems.map((item) => (
            <NavLink
              key={item.path}
              to={item.path}
              className={({ isActive }) =>
                `block rounded-md px-3 py-2 text-sm transition-colors ${
                  isActive ? 'bg-indigo-600 text-white' : 'text-gray-300 hover:bg-gray-800 hover:text-white'
                }`
              }
            >
              {item.title}
            </NavLink>
          ))}
        </nav>
      </aside>

      {/* 主区域 */}
      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex h-14 shrink-0 items-center justify-between border-b border-gray-200 bg-white px-6">
          <h1 className="text-lg font-semibold text-gray-900">{currentTitle}</h1>
          <div className="flex items-center gap-4">
            <span
              className="h-2 w-2 rounded-full"
              style={{ background: connected ? '#22c55e' : '#ef4444' }}
              title={connected ? '实时连接已建立' : '实时连接断开'}
            />
            <span className="text-sm text-gray-700">{user?.username || '用户'}</span>
            <button
              type="button"
              onClick={() => logout()}
              className="rounded-md border border-gray-300 px-3 py-1.5 text-sm text-gray-700 transition-colors hover:bg-gray-50"
            >
              退出
            </button>
          </div>
        </header>
        <main className="flex-1 overflow-y-auto p-6">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
