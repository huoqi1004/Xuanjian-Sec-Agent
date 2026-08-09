import { useEffect, useRef, useState } from 'react';
import type { KeyboardEvent } from 'react';
import { aiApi } from '@/api';
import type { ChatMessage } from '@/api';
import Badge from '@/components/ui/badge';
import Button from '@/components/ui/button';
import { useToast } from '@/components/ui/use-toast';

const CONVERSATION_ID = 'default';

const WELCOME: ChatMessage = {
  role: 'assistant',
  content:
    '👋 您好！我是玄鉴安全智能体，基于DeepSeek V4 Pro驱动的AI安全助手。\n\n' +
    '我可以帮助您：\n\n' +
    '📊 报告生成\n- 生成每日/每周/每月安全报告\n- 生成扫描报告和基线检查报告\n\n' +
    '🔍 威胁情报查询\n- 查询IP、域名、哈希等威胁指标\n- 分析恶意软件哈希\n\n' +
    '⚠️ 告警分析\n- 查看和筛选安全告警\n- 深度分析告警数据\n\n' +
    '🔧 系统操作\n- 检查系统健康状态\n- 管理对话历史\n\n' +
    '💬 您可以直接输入问题或使用命令与我交流。输入 "help" 查看所有可用命令。'
};

const fieldCls =
  'w-full rounded-md border border-cyan-500/20 bg-[#1a2340] px-3 py-2 text-sm text-gray-200 outline-none transition-colors placeholder:text-gray-500 focus:border-cyan-500/60';

export default function Assistant() {
  const { toast } = useToast();
  const [messages, setMessages] = useState<ChatMessage[]>([WELCOME]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    loadHistory();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    const el = scrollRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [messages, loading]);

  async function loadHistory() {
    try {
      const data = await aiApi.history(CONVERSATION_ID);
      if (data.messages && data.messages.length > 0) {
        setMessages(data.messages);
      }
    } catch {
      // http 拦截器已提示
    }
  }

  async function sendMessage() {
    const text = input.trim();
    if (!text || loading) return;
    setMessages((prev) => [...prev, { role: 'user', content: text }]);
    setInput('');
    setLoading(true);
    try {
      const reply = await aiApi.chat(text, CONVERSATION_ID);
      setMessages((prev) => [
        ...prev,
        { role: 'assistant', content: reply.content, is_report: reply.is_report }
      ]);
    } catch {
      setMessages((prev) => [...prev, { role: 'assistant', content: '❌ 网络错误，请稍后重试' }]);
    } finally {
      setLoading(false);
    }
  }

  async function clearHistory() {
    try {
      await aiApi.clearHistory(CONVERSATION_ID);
      setMessages([{ role: 'assistant', content: '✅ 对话历史已清除。我现在是全新的状态，可以重新开始对话。' }]);
      toast({ title: '对话历史已清除', variant: 'success' });
    } catch {
      // http 拦截器已提示
    }
  }

  function handleKeyDown(e: KeyboardEvent<HTMLTextAreaElement>) {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      sendMessage();
    }
  }

  return (
    <div className="flex h-[calc(100vh-9rem)] flex-col">
      {/* 页头 */}
      <div className="mb-4 flex items-center justify-between">
        <div>
          <h2 className="text-xl font-bold text-white">AI安全助手</h2>
          <p className="mt-1 text-sm text-gray-400">智能对话 · 报告生成 · 威胁分析 · 告警查询</p>
        </div>
        <Button size="sm" variant="destructive" onClick={clearHistory}>
          清除对话
        </Button>
      </div>

      {/* 聊天区 */}
      <div className="flex min-h-0 flex-1 flex-col rounded-lg border border-cyan-500/20 bg-[#16213e]/80">
        <div ref={scrollRef} className="flex-1 space-y-4 overflow-y-auto px-4 py-4">
          {messages.map((msg, idx) => {
            const isUser = msg.role === 'user';
            return (
              <div
                key={idx}
                className={`flex items-start gap-3 ${isUser ? 'flex-row-reverse' : ''}`}
              >
                <div
                  className={`flex h-9 w-9 shrink-0 items-center justify-center rounded-full text-base ${
                    isUser
                      ? 'bg-gradient-to-br from-indigo-500 to-purple-600'
                      : 'border border-cyan-500/30 bg-cyan-500/10'
                  }`}
                >
                  {isUser ? '👤' : '🤖'}
                </div>
                <div className={`flex max-w-[78%] flex-col ${isUser ? 'items-end' : 'items-start'}`}>
                  {msg.is_report && (
                    <div className="mb-1">
                      <Badge variant="success">报告</Badge>
                    </div>
                  )}
                  <div
                    className={`rounded-lg px-4 py-2.5 text-sm leading-relaxed ${
                      isUser
                        ? 'bg-gradient-to-r from-indigo-600 to-indigo-700 text-white'
                        : 'border border-cyan-500/20 bg-[#0f1a33] text-gray-200'
                    }`}
                  >
                    <pre className="whitespace-pre-wrap font-sans">{msg.content}</pre>
                  </div>
                </div>
              </div>
            );
          })}

          {loading && (
            <div className="flex items-start gap-3">
              <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full border border-cyan-500/30 bg-cyan-500/10">
                🤖
              </div>
              <div className="rounded-lg border border-cyan-500/20 bg-[#0f1a33] px-4 py-3">
                <div className="flex items-center gap-1.5">
                  <span className="typing-dot h-1.5 w-1.5 rounded-full bg-cyan-400" />
                  <span className="typing-dot h-1.5 w-1.5 rounded-full bg-cyan-400" />
                  <span className="typing-dot h-1.5 w-1.5 rounded-full bg-cyan-400" />
                </div>
              </div>
            </div>
          )}
        </div>

        {/* 输入区 */}
        <div className="flex items-end gap-3 border-t border-white/5 p-3">
          <textarea
            className={`${fieldCls} min-h-[44px] flex-1 resize-none`}
            rows={2}
            value={input}
            disabled={loading}
            placeholder="输入消息，Enter发送，Shift+Enter换行..."
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={handleKeyDown}
          />
          <Button disabled={loading || !input.trim()} onClick={sendMessage}>
            {loading ? '思考中…' : '发送'}
          </Button>
        </div>
      </div>

      <style>{`
        .typing-dot { animation: typingBlink 1.2s infinite ease-in-out; }
        .typing-dot:nth-child(2) { animation-delay: 0.2s; }
        .typing-dot:nth-child(3) { animation-delay: 0.4s; }
        @keyframes typingBlink {
          0%, 60%, 100% { opacity: 0.25; transform: translateY(0); }
          30% { opacity: 1; transform: translateY(-3px); }
        }
      `}</style>
    </div>
  );
}
