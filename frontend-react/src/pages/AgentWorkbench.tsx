import { useCallback, useEffect, useState } from 'react';
import { agentApi } from '@/api';
import Badge from '@/components/ui/badge';
import Button from '@/components/ui/button';
import Card, { CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import Dialog from '@/components/ui/dialog';
import Textarea from '@/components/ui/textarea';
import { useToast } from '@/components/ui/use-toast';

interface AgentStep {
  tool: string;
  reason?: string;
  params?: unknown;
}

interface AgentResult {
  tool: string;
  success?: boolean;
  require_confirmation?: boolean;
  confirmation_id?: string;
  data?: unknown;
  error?: string;
  reason?: string;
  params?: unknown;
}

interface AgentPlan {
  goal?: string;
  steps?: AgentStep[];
}

interface AgentRunResult {
  results?: AgentResult[];
  summary?: string;
  confirmation_required?: boolean;
}

/** 判断工具风险是否为高危（兼容后端可能返回 high/高危/critical 等） */
function isHighRisk(risk?: string) {
  if (!risk) return false;
  const r = risk.toLowerCase();
  return r.includes('high') || r.includes('高危') || r.includes('critical') || r.includes('严重');
}

/** 展示工具风险标签：高危 → 红色 Badge */
function renderRiskBadge(tool: string, toolsMap: Record<string, string>) {
  const risk = toolsMap[tool];
  if (!isHighRisk(risk)) return null;
  return <Badge variant="danger">高危需确认</Badge>;
}

function renderJson(data: unknown) {
  try {
    return JSON.stringify(data, null, 2);
  } catch {
    return String(data);
  }
}

export default function AgentWorkbench() {
  const { toast } = useToast();
  const [task, setTask] = useState('');
  const [planning, setPlanning] = useState(false);
  const [running, setRunning] = useState(false);
  const [plan, setPlan] = useState<AgentPlan | null>(null);
  const [result, setResult] = useState<AgentRunResult | null>(null);
  /** 工具元数据映射：tool name → risk */
  const [toolsMap, setToolsMap] = useState<Record<string, string>>({});
  /** 执行结果中等待人工确认的项（弹窗用） */
  const [confirmItem, setConfirmItem] = useState<AgentResult | null>(null);
  const [confirming, setConfirming] = useState(false);
  /** 服务端等待确认队列（10s 轮询） */
  const [pending, setPending] = useState<any[]>([]);

  const fetchTools = useCallback(async () => {
    try {
      const tools = await agentApi.tools();
      if (Array.isArray(tools)) {
        const map: Record<string, string> = {};
        for (const t of tools as Array<{ name?: string; risk?: string }>) {
          if (t?.name) map[t.name] = t.risk || '';
        }
        setToolsMap(map);
      }
    } catch {
      // 工具元数据拉取失败不影响主流程（http 拦截器已提示）
    }
  }, []);

  const fetchPending = useCallback(async () => {
    try {
      const list = await agentApi.pending();
      if (Array.isArray(list)) setPending(list);
    } catch {
      // 忽略轮询错误，下次继续
    }
  }, []);

  // 挂载：拉取工具元数据 + 待确认列表，并 10s 轮询 pending
  useEffect(() => {
    fetchTools();
    fetchPending();
    const timer = setInterval(fetchPending, 10000);
    return () => clearInterval(timer);
  }, [fetchTools, fetchPending]);

  async function previewPlan() {
    if (!task.trim()) {
      toast({ title: '请输入任务描述', variant: 'warning' });
      return;
    }
    setPlanning(true);
    try {
      const p = await agentApi.plan(task.trim());
      setPlan(p as AgentPlan);
      toast({ title: '计划已生成', description: (p as AgentPlan)?.goal });
    } catch {
      // http 拦截器已提示
    } finally {
      setPlanning(false);
    }
  }

  async function runTask() {
    if (!task.trim()) {
      toast({ title: '请输入任务描述', variant: 'warning' });
      return;
    }
    setRunning(true);
    try {
      const r = (await agentApi.run(task.trim())) as AgentRunResult;
      setResult(r);
      const confirm = r.results?.find((x) => x.require_confirmation && x.confirmation_id);
      if (confirm) {
        setConfirmItem(confirm);
      } else {
        toast({ title: '执行完成', description: r.summary });
      }
    } catch {
      // http 拦截器已提示
    } finally {
      setRunning(false);
    }
  }

  /** 弹窗内人工确认：确认后提示已处理，不自动重跑，由用户再点执行 */
  async function confirmDecision(decision: 'approve' | 'reject') {
    if (!confirmItem?.confirmation_id) return;
    setConfirming(true);
    try {
      await agentApi.confirm(confirmItem.confirmation_id, decision);
      toast({
        title: decision === 'approve' ? '已批准执行' : '已拒绝',
        description: '处理完成，请重新执行任务获取结果'
      });
      setConfirmItem(null);
      fetchPending();
    } catch {
      // http 拦截器已提示
    } finally {
      setConfirming(false);
    }
  }

  /** pending 队列内直接批准/拒绝 */
  async function handlePendingDecision(item: any, decision: 'approve' | 'reject') {
    if (!item?.confirmation_id) return;
    try {
      await agentApi.confirm(item.confirmation_id, decision);
      toast({ title: decision === 'approve' ? '已批准执行' : '已拒绝' });
      fetchPending();
    } catch {
      // http 拦截器已提示
    }
  }

  return (
    <div className="space-y-4">
      {/* 任务输入 */}
      <Card>
        <CardHeader>
          <CardTitle>多 Agent 安全任务工作台</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <Textarea
            value={task}
            onChange={(e) => setTask(e.target.value)}
            placeholder="输入自然语言安全任务，如：分析内网资产风险"
            rows={3}
          />
          <div className="flex gap-2">
            <Button variant="outline" onClick={previewPlan} disabled={running || planning || !task.trim()}>
              {planning ? '生成中…' : '预览计划'}
            </Button>
            <Button onClick={runTask} disabled={running || planning || !task.trim()}>
              {running ? '执行中…' : '执行任务'}
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* 执行计划 */}
      {plan && (
        <Card>
          <CardHeader>
            <CardTitle>执行计划</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            {plan.goal && (
              <p className="text-sm text-gray-700">
                <span className="font-semibold">目标：</span>
                {plan.goal}
              </p>
            )}
            {plan.steps?.length ? (
              <ol className="space-y-2">
                {plan.steps.map((s, i) => (
                  <li key={i} className="border-l-2 border-indigo-200 py-1 pl-3">
                    <div className="flex flex-wrap items-center gap-2 text-sm">
                      <span>
                        第{i + 1}步：<span className="font-medium">{s.tool}</span>
                      </span>
                      {renderRiskBadge(s.tool, toolsMap)}
                      {s.reason && <span className="text-gray-500">（{s.reason}）</span>}
                    </div>
                    {s.params != null && (
                      <pre className="mt-1 max-h-32 overflow-auto rounded bg-gray-50 p-2 text-xs text-gray-600">
                        {renderJson(s.params)}
                      </pre>
                    )}
                  </li>
                ))}
              </ol>
            ) : (
              <p className="text-sm text-gray-500">未生成步骤</p>
            )}
          </CardContent>
        </Card>
      )}

      {/* 执行结果 */}
      {result && (
        <Card>
          <CardHeader>
            <CardTitle>执行结果</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            {result.results?.length ? (
              result.results.map((r, i) => (
                <div key={i} className="rounded-md border border-gray-100 bg-gray-50 p-3">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-sm font-medium">{r.tool}</span>
                    {r.success ? (
                      <Badge variant="success">成功</Badge>
                    ) : r.require_confirmation ? (
                      <Badge variant="warning">等待人工确认</Badge>
                    ) : (
                      <Badge variant="danger">失败</Badge>
                    )}
                  </div>
                  {r.success && r.data != null && (
                    <pre className="mt-2 max-h-40 overflow-auto rounded bg-gray-900 p-2 text-xs text-gray-100">
                      {renderJson(r.data)}
                    </pre>
                  )}
                  {!r.success && r.error && <p className="mt-1 text-xs text-red-600">{r.error}</p>}
                </div>
              ))
            ) : (
              <p className="text-sm text-gray-500">无执行步骤</p>
            )}
            {result.summary && (
              <div className="mt-3 whitespace-pre-wrap border-t border-gray-100 pt-3 text-sm text-gray-700">
                {result.summary}
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {/* 服务端等待确认队列（轮询） */}
      {pending.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle>等待人工确认（{pending.length}）</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            {pending.map((item: any, i: number) => (
              <div
                key={item.confirmation_id || i}
                className="flex items-start justify-between gap-3 rounded-md border border-gray-100 bg-gray-50 p-3"
              >
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-sm font-medium">{item.tool || item.name || '未知工具'}</span>
                    <Badge variant="danger">高危需确认</Badge>
                  </div>
                  {item.params != null && (
                    <pre className="mt-1 max-h-24 overflow-auto text-xs text-gray-500">{renderJson(item.params)}</pre>
                  )}
                </div>
                <div className="flex shrink-0 gap-2">
                  <Button size="sm" variant="destructive" onClick={() => handlePendingDecision(item, 'reject')}>
                    拒绝
                  </Button>
                  <Button size="sm" onClick={() => handlePendingDecision(item, 'approve')}>
                    批准
                  </Button>
                </div>
              </div>
            ))}
          </CardContent>
        </Card>
      )}

      {/* 人工确认弹窗 */}
      <Dialog
        open={!!confirmItem}
        onOpenChange={(open) => {
          if (!open && !confirming) setConfirmItem(null);
        }}
        title="高危动作需要人工确认"
        footer={
          <>
            <Button variant="destructive" disabled={confirming} onClick={() => confirmDecision('reject')}>
              拒绝
            </Button>
            <Button disabled={confirming} onClick={() => confirmDecision('approve')}>
              批准执行
            </Button>
          </>
        }
      >
        <div className="space-y-2 text-sm text-gray-700">
          <p>
            <span className="font-medium">工具：</span>
            {confirmItem?.tool}
          </p>
          {confirmItem?.reason && (
            <p>
              <span className="font-medium">原因：</span>
              {confirmItem.reason}
            </p>
          )}
          {confirmItem?.params != null && (
            <>
              <p className="font-medium">参数：</p>
              <pre className="max-h-40 overflow-auto rounded bg-gray-900 p-2 text-xs text-gray-100">
                {renderJson(confirmItem.params)}
              </pre>
            </>
          )}
        </div>
      </Dialog>
    </div>
  );
}
