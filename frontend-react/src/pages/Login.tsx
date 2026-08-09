import { useEffect, useState, type FormEvent } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { useUserStore } from '@/stores/user';
import Button from '@/components/ui/button';
import Input from '@/components/ui/input';
import { useToast } from '@/components/ui/use-toast';

const REMEMBER_KEY = 'xuanjian_remember';

export default function Login() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const { toast } = useToast();
  const login = useUserStore((s) => s.login);
  const token = useUserStore((s) => s.token);
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [remember, setRemember] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    // 已登录则直接跳转
    if (token) {
      navigate(searchParams.get('redirect') || '/dashboard', { replace: true });
      return;
    }
    const saved = localStorage.getItem(REMEMBER_KEY);
    if (saved) {
      try {
        const data = JSON.parse(saved);
        setUsername(data.username || '');
        setPassword(data.password || '');
        setRemember(true);
      } catch {
        /* ignore */
      }
    }
  }, [token, navigate, searchParams]);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    if (username.length < 3 || username.length > 20) {
      setError('用户名长度在3到20个字符');
      return;
    }
    if (password.length < 6 || password.length > 32) {
      setError('密码长度在6到32个字符');
      return;
    }
    setLoading(true);
    setError('');
    try {
      await login(username, password);
      if (remember) {
        localStorage.setItem(REMEMBER_KEY, JSON.stringify({ username, password }));
      } else {
        localStorage.removeItem(REMEMBER_KEY);
      }
      toast({ title: '登录成功，正在跳转...', variant: 'success' });
      navigate(searchParams.get('redirect') || '/dashboard', { replace: true });
    } catch {
      setError('登录失败，请检查用户名和密码');
    } finally {
      setLoading(false);
    }
  }

  function showForgotTip() {
    toast({ title: '请联系系统管理员重置密码' });
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
            <div className="relative">
              <Input
                id="password"
                type={showPassword ? 'text' : 'password'}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="请输入密码"
                autoComplete="current-password"
                className="border-cyan-500/20 bg-black/40 pr-10 text-gray-100 placeholder:text-white/30"
              />
              <button
                type="button"
                onClick={() => setShowPassword((v) => !v)}
                aria-label={showPassword ? '隐藏密码' : '显示密码'}
                className="absolute right-2 top-1/2 -translate-y-1/2 text-white/40 transition-colors hover:text-cyan-400"
              >
                <svg
                  width="16"
                  height="16"
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="2"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                >
                  {showPassword ? (
                    <>
                      <path d="M9.88 9.88a3 3 0 1 0 4.24 4.24" />
                      <path d="M10.73 5.08A10.43 10.43 0 0 1 12 5c7 0 10 7 10 7a13.16 13.16 0 0 1-1.67 2.68" />
                      <path d="M6.61 6.61A13.526 13.526 0 0 0 2 12s3 7 10 7a9.74 9.74 0 0 0 5.39-1.61" />
                      <line x1="2" y1="2" x2="22" y2="22" />
                    </>
                  ) : (
                    <>
                      <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" />
                      <circle cx="12" cy="12" r="3" />
                    </>
                  )}
                </svg>
              </button>
            </div>
          </div>

          <div className="flex items-center justify-between">
            <label className="flex cursor-pointer items-center gap-2 text-xs text-white/50">
              <input
                type="checkbox"
                checked={remember}
                onChange={(e) => setRemember(e.target.checked)}
                className="h-3.5 w-3.5 accent-cyan-400"
              />
              记住我
            </label>
            <button
              type="button"
              onClick={showForgotTip}
              className="text-xs text-cyan-400/70 transition-colors hover:text-cyan-400"
            >
              忘记密码?
            </button>
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
