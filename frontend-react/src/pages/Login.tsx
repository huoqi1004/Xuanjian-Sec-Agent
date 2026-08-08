import { useState, type FormEvent } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { useUserStore } from '@/stores/user';
import Button from '@/components/ui/button';
import Input from '@/components/ui/input';

export default function Login() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const login = useUserStore((s) => s.login);
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    if (!username || !password) {
      setError('请输入用户名和密码');
      return;
    }
    setLoading(true);
    setError('');
    try {
      await login(username, password);
      navigate(searchParams.get('redirect') || '/dashboard', { replace: true });
    } catch {
      setError('登录失败，请检查用户名和密码');
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-gradient-to-br from-[#0a0a1a] via-[#1a1a2e] to-[#16213e] p-4">
      <div className="w-full max-w-[400px] rounded-2xl border border-cyan-500/20 bg-[#16213e]/85 p-10 shadow-xl backdrop-blur">
        <div className="text-center">
          <div className="mx-auto mb-4 h-16 w-16 rounded-full border-2 border-cyan-400/60 bg-gradient-to-br from-cyan-400/20 to-purple-500/20" />
          <h1 className="text-2xl font-bold tracking-wider text-transparent bg-gradient-to-r from-cyan-400 to-purple-400 bg-clip-text">
            玄鉴安全智能体
          </h1>
          <p className="mt-2 text-xs tracking-widest text-white/40">多引擎协同安全评估系统</p>
        </div>

        <form onSubmit={handleSubmit} className="mt-8 space-y-4">
          <div>
            <label className="mb-1.5 block text-xs text-white/70" htmlFor="username">
              用户名
            </label>
            <Input
              id="username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="请输入用户名"
              autoComplete="username"
              className="border-cyan-500/20 bg-black/40 text-gray-100 placeholder:text-white/30"
            />
          </div>
          <div>
            <label className="mb-1.5 block text-xs text-white/70" htmlFor="password">
              密码
            </label>
            <Input
              id="password"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="请输入密码"
              autoComplete="current-password"
              className="border-cyan-500/20 bg-black/40 text-gray-100 placeholder:text-white/30"
            />
          </div>

          {error && <div className="text-sm text-red-400">{error}</div>}

          <Button
            type="submit"
            disabled={loading}
            className="w-full bg-gradient-to-r from-cyan-500 to-purple-600 text-base font-semibold tracking-widest hover:from-cyan-400 hover:to-purple-500 disabled:opacity-60"
          >
            {loading ? '登录中...' : '登 录'}
          </Button>
        </form>

        <p className="mt-6 text-center text-xs text-white/30">默认账号：admin / admin123</p>
      </div>
    </div>
  );
}
