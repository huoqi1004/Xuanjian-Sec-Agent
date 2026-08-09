import { useCallback, useEffect, useMemo, useState } from 'react';
import type { EChartsOption } from 'echarts';
import { baselineApi } from '@/api';
import type { BaselineCheckResult, BaselinePolicy, BaselineResultsData } from '@/api';
import EChart from '@/components/chart';
import Badge from '@/components/ui/badge';
import Button from '@/components/ui/button';
import { Table } from '@/components/ui/table';
import { useToast } from '@/components/ui/use-toast';

const POLL_INTERVAL = 2000;
const MAX_POLL_ATTEMPTS = 15;

const fieldCls =
  'rounded-md border border-cyan-500/20 bg-[#1a2340] px-3 py-2 text-sm text-gray-300 outline-none transition-colors placeholder:text-gray-500 focus:border-cyan-500/60';

interface TagInfo {
  label: string;
  variant: 'default' | 'success' | 'warning' | 'danger';
}

interface BaselineRow {
  check_name: string;
  expected_value: string;
  actual_value: string;
  status: string;
  severity: string;
  remediation: string;
}

interface RecentTask {
  task_id: string;
  policy_name: string;
  status: string;
  created_at: string;
}

function getSeverityTag(s: string): TagInfo {
  const map: Record<string, TagInfo> = {
    critical: { label: '严重', variant: 'danger' },
    high: { label: '高危', variant: 'warning' },
    medium: { label: '中危', variant: 'default' },
    low: { label: '低危', variant: 'success' }
  };
  return map[s] || { label: s || '-', variant: 'default' };
}

function getCheckStatusTag(s: string): TagInfo {
  const map: Record<string, TagInfo> = {
    pass: { label: '通过', variant: 'success' },
    fail: { label: '失败', variant: 'danger' },
    warn: { label: '警告', variant: 'warning' }
  };
  return map[s] || { label: s || '-', variant: 'default' };
}

function demoBaselineResults(): BaselineCheckResult[] {
  return [
    {
      check_name: 'SSH最大认证尝试次数',
      expected_value: 'MaxAuthTries 4',
      actual_value: 'MaxAuthTries 6',
      status: 'fail',
      severity: 'high',
      remediation: '编辑/etc/ssh/sshd_config，设置MaxAuthTries为4'
    },
    {
      check_name: '密码复杂度策略',
      expected_value: 'minlen=12',
      actual_value: 'minlen=5',
      status: 'fail',
      severity: 'critical',
      remediation: '修改/etc/pam.d/common-password，设置最小密码长度为12'
    },
    {
      check_name: '系统日志审计',
      expected_value: 'auditd运行中',
      actual_value: 'auditd已停止',
      status: 'fail',
      severity: 'high',
      remediation: '执行systemctl enable --now auditd'
    },
    {
      check_name: '防火墙状态',
      expected_value: 'ufw启用',
      actual_value: 'ufw未启用',
      status: 'fail',
      severity: 'critical',
      remediation: '执行ufw enable启用防火墙'
    },
    {
      check_name: 'SSH Root登录',
      expected_value: 'PermitRootLogin no',
      actual_value: 'PermitRootLogin yes',
      status: 'fail',
      severity: 'high',
      remediation: '编辑/etc/ssh/sshd_config，设置PermitRootLogin为no'
    },
    {
      check_name: '文件权限检查',
      expected_value: '/etc/passwd 644',
      actual_value: '/etc/passwd 644',
      status: 'pass',
      severity: 'low',
      remediation: '无需修复'
    },
    {
      check_name: 'NTP时间同步',
      expected_value: 'chrony运行中',
      actual_value: 'chrony运行中',
      status: 'pass',
      severity: 'low',
      remediation: '无需修复'
    },
    {
      check_name: '内核参数配置',
      expected_value: 'net.ipv4.tcp_syncookies=1',
      actual_value: 'net.ipv4.tcp_syncookies=0',
      status: 'fail',
      severity: 'medium',
      remediation: '执行sysctl -w net.ipv4.tcp_syncookies=1'
    },
    {
      check_name: 'SUID文件检查',
      expected_value: '无异常SUID文件',
      actual_value: '发现3个异常SUID文件',
      status: 'fail',
      severity: 'high',
      remediation: '检查并移除不必要的SUID权限'
    },
    {
      check_name: '用户密码过期策略',
      expected_value: 'PASS_MAX_DAYS 90',
      actual_value: 'PASS_MAX_DAYS 99999',
      status: 'fail',
      severity: 'medium',
      remediation: '编辑/etc/login.defs，设置PASS_MAX_DAYS为90'
    },
    {
      check_name: 'SSH空闲超时',
      expected_value: 'ClientAliveInterval 300',
      actual_value: '未配置',
      status: 'fail',
      severity: 'medium',
      remediation: '编辑/etc/ssh/sshd_config，添加ClientAliveInterval 300'
    },
    {
      check_name: 'IP转发检查',
      expected_value: 'net.ipv4.ip_forward=0',
      actual_value: 'net.ipv4.ip_forward=1',
      status: 'fail',
      severity: 'medium',
      remediation: '执行sysctl -w net.ipv4.ip_forward=0'
    }
  ];
}

const demoPolicies: BaselinePolicy[] = [
  { id: 1, name: 'CIS Debian', description: 'Debian 系统安全基线', standard: 'CIS' },
  { id: 2, name: 'CIS Windows', description: 'Windows 系统安全基线', standard: 'CIS' },
  { id: 3, name: '等保2.0', description: '等保2.0 三级安全基线', standard: '等保2.0' }
];

export default function Baseline() {
  const { toast } = useToast();
  const [policies, setPolicies] = useState<BaselinePolicy[]>([]);
  const [selectedPolicyId, setSelectedPolicyId] = useState<number | null>(null);
  const [checking, setChecking] = useState(false);
  const [results, setResults] = useState<BaselineRow[]>([]);
  const [showResults, setShowResults] = useState(false);
  const [complianceRate, setComplianceRate] = useState(0);
  const [viewingTaskId, setViewingTaskId] = useState('');
  const [recentTasks, setRecentTasks] = useState<RecentTask[]>([]);

  const loadPolicies = useCallback(async () => {
    try {
      const list = await baselineApi.policies();
      setPolicies(list || []);
      setSelectedPolicyId((prev) => prev ?? (list.length > 0 ? list[0].id : null));
    } catch {
      setPolicies(demoPolicies);
      setSelectedPolicyId((prev) => prev ?? 1);
    }
  }, []);

  useEffect(() => {
    loadPolicies();
  }, [loadPolicies]);

  function applyResults(data: BaselineResultsData | null, rows: BaselineCheckResult[], fallbackRate?: number) {
    const mapped: BaselineRow[] = rows.map((r) => ({
      check_name: r.check_name || r.check_id || '-',
      expected_value: r.expected_value || '-',
      actual_value: r.actual_value || '-',
      status: r.status || '',
      severity: r.severity || '',
      remediation: r.remediation || ''
    }));
    setResults(mapped);
    if (fallbackRate !== undefined) {
      setComplianceRate(fallbackRate);
    } else {
      // 优先后端 stats.compliance_rate，否则按 Vue 版口径（低危或 pass 计为合规）
      const statsRate = data?.stats?.compliance_rate;
      const rate = statsRate !== undefined ? Number(statsRate) : NaN;
      if (!Number.isNaN(rate)) {
        setComplianceRate(Math.round(rate));
      } else {
        const passCount = mapped.filter((r) => r.severity === 'low' || r.status === 'pass').length;
        setComplianceRate(mapped.length > 0 ? Math.round((passCount / mapped.length) * 100) : 0);
      }
    }
    setShowResults(true);
    setChecking(false);
  }

  /** 轮询检查结果：每 2s 拉取一次，直到拿到结果或超时（超时走演示数据） */
  function pollResults(taskId: string): Promise<void> {
    return new Promise((resolve) => {
      let attempts = 0;
      const timer = setInterval(async () => {
        attempts++;
        try {
          const data = await baselineApi.results(taskId);
          const rows = Array.isArray(data) ? data : data.results || [];
          if (rows.length > 0) {
            clearInterval(timer);
            applyResults(data, rows);
            resolve();
            return;
          }
        } catch {
          // 单次轮询失败，继续等待
        }
        if (attempts >= MAX_POLL_ATTEMPTS) {
          clearInterval(timer);
          applyResults(null, demoBaselineResults(), 75);
          resolve();
        }
      }, POLL_INTERVAL);
    });
  }

  async function startCheck() {
    if (!selectedPolicyId) {
      toast({ title: '请选择基线策略', variant: 'warning' });
      return;
    }
    setChecking(true);
    setShowResults(false);
    try {
      const t = await baselineApi.check(selectedPolicyId);
      setViewingTaskId(t.task_id);
      setRecentTasks((prev) =>
        [
          {
            task_id: t.task_id,
            policy_name: t.policy_name || '',
            status: t.status || 'running',
            created_at: new Date().toLocaleString('zh-CN')
          },
          ...prev
        ].slice(0, 10)
      );
      await pollResults(t.task_id);
    } catch {
      // 启动检查失败则走演示数据（与 Vue 版一致）
      applyResults(null, demoBaselineResults(), 75);
    }
  }

  async function viewTask(taskId: string) {
    setViewingTaskId(taskId);
    setChecking(true);
    setShowResults(false);
    await pollResults(taskId);
  }

  // 合规率仪表盘
  const gaugeOption = useMemo<EChartsOption>(
    () => ({
      series: [
        {
          type: 'gauge',
          startAngle: 200,
          endAngle: -20,
          min: 0,
          max: 100,
          splitNumber: 10,
          itemStyle: {
            color: {
              type: 'linear',
              x: 0,
              y: 0,
              x2: 0,
              y2: 1,
              colorStops: [
                { offset: 0, color: '#00d4ff' },
                { offset: 1, color: '#7c3aed' }
              ]
            }
          },
          progress: { show: true, width: 16 },
          pointer: { show: false },
          axisLine: { lineStyle: { width: 16, color: [[1, 'rgba(0,212,255,0.1)']] } },
          axisTick: { show: false },
          splitLine: { show: false },
          axisLabel: { show: false },
          title: { show: true, offsetCenter: [0, '60%'], fontSize: 14, color: 'rgba(255,255,255,0.5)' },
          detail: {
            valueAnimation: true,
            fontSize: 36,
            offsetCenter: [0, '10%'],
            color: '#00d4ff',
            formatter: '{value}%'
          },
          data: [{ value: complianceRate, name: '合规率' }]
        }
      ]
    }),
    [complianceRate]
  );

  const summary = useMemo(() => {
    const compliant = results.filter((r) => r.severity === 'low').length;
    const nonCompliant = results.filter((r) => r.severity !== 'low').length;
    const critical = results.filter((r) => r.severity === 'high' || r.severity === 'critical').length;
    return { compliant, nonCompliant, critical, total: results.length };
  }, [results]);

  return (
    <div className="space-y-5">
      {/* 页头 */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-bold text-white">基线排查</h2>
          <p className="mt-1 text-sm text-gray-400">根据安全基线标准对系统配置进行检查</p>
        </div>
      </div>

      {/* 基线策略 */}
      <div className="rounded-lg border border-cyan-500/20 bg-[#16213e]/80 p-5">
        <div className="mb-4 text-sm font-semibold text-cyan-300">基线策略</div>
        <div className="flex flex-wrap items-center gap-3">
          <select
            className={`${fieldCls} w-[220px]`}
            value={selectedPolicyId ?? ''}
            onChange={(e) => setSelectedPolicyId(Number(e.target.value))}
          >
            {policies.map((p) => (
              <option key={p.id} value={p.id}>
                {p.name}
              </option>
            ))}
          </select>
          <Button size="sm" disabled={checking || !selectedPolicyId} onClick={startCheck}>
            {checking ? '检查中…' : '启动检查'}
          </Button>
          <span className="text-xs text-gray-500">检查主机默认 localhost</span>
        </div>
        <div className="mt-4">
          <Table>
            <thead>
              <tr className="border-b border-cyan-500/20 text-left text-xs text-cyan-200/70">
                <th className="px-2 py-2 font-medium">ID</th>
                <th className="px-2 py-2 font-medium">策略名称</th>
                <th className="px-2 py-2 font-medium">描述</th>
                <th className="px-2 py-2 font-medium">标准</th>
                <th className="px-2 py-2 font-medium">检查项数</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5">
              {policies.map((p) => (
                <tr key={p.id} className="hover:bg-white/5">
                  <td className="px-2 py-2 text-gray-400">{p.id}</td>
                  <td className="px-2 py-2 text-gray-300">{p.name}</td>
                  <td className="px-2 py-2 text-gray-400">{p.description || '-'}</td>
                  <td className="px-2 py-2">
                    <Badge variant="default">{p.standard || '-'}</Badge>
                  </td>
                  <td className="px-2 py-2 text-gray-300">{p.checks?.length ?? 0}</td>
                </tr>
              ))}
              {policies.length === 0 && (
                <tr>
                  <td colSpan={5} className="px-2 py-6 text-center text-gray-500">暂无基线策略</td>
                </tr>
              )}
            </tbody>
          </Table>
        </div>
      </div>

      {/* 最近检查任务 */}
      <div className="rounded-lg border border-cyan-500/20 bg-[#16213e]/80 p-5">
        <div className="mb-4 text-sm font-semibold text-cyan-300">最近检查任务</div>
        <Table>
          <thead>
            <tr className="border-b border-cyan-500/20 text-left text-xs text-cyan-200/70">
              <th className="px-2 py-2 font-medium">任务ID</th>
              <th className="px-2 py-2 font-medium">策略</th>
              <th className="px-2 py-2 font-medium">状态</th>
              <th className="px-2 py-2 font-medium">发起时间</th>
              <th className="px-2 py-2 font-medium">操作</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-white/5">
            {recentTasks.map((t) => (
              <tr key={t.task_id} className="hover:bg-white/5">
                <td className="px-2 py-2 text-gray-400">{t.task_id}</td>
                <td className="px-2 py-2 text-gray-300">{t.policy_name || '-'}</td>
                <td className="px-2 py-2">
                  <Badge variant={t.status === 'running' ? 'warning' : 'success'}>
                    {t.status === 'running' ? '运行中' : '已完成'}
                  </Badge>
                </td>
                <td className="px-2 py-2 text-gray-400">{t.created_at}</td>
                <td className="px-2 py-2">
                  <button
                    type="button"
                    onClick={() => viewTask(t.task_id)}
                    className="text-xs text-cyan-400 transition-colors hover:text-cyan-300"
                  >
                    查看结果
                  </button>
                </td>
              </tr>
            ))}
            {recentTasks.length === 0 && (
              <tr>
                <td colSpan={5} className="px-2 py-6 text-center text-gray-500">暂无检查任务，请选择策略启动检查</td>
              </tr>
            )}
          </tbody>
        </Table>
      </div>

      {/* 检查中 */}
      {checking && (
        <div className="rounded-lg border border-cyan-500/20 bg-[#16213e]/60 py-12 text-center">
          <div className="mx-auto h-10 w-10 animate-spin rounded-full border-2 border-cyan-400 border-t-transparent" />
          <div className="mt-4 text-sm text-gray-300">正在进行基线检查，请稍候...</div>
        </div>
      )}

      {/* 检查结果 */}
      {showResults && !checking && (
        <div className="space-y-5">
          <div className="grid grid-cols-1 gap-5 lg:grid-cols-2">
            <div className="rounded-lg border border-cyan-500/20 bg-[#16213e]/80 p-5">
              <div className="mb-4 text-sm font-semibold text-cyan-300">合规率仪表盘</div>
              <EChart option={gaugeOption} className="h-[280px]" />
            </div>
            <div className="rounded-lg border border-cyan-500/20 bg-[#16213e]/80 p-5">
              <div className="mb-4 text-sm font-semibold text-cyan-300">
                检查概要{viewingTaskId ? `（任务 ${viewingTaskId}）` : ''}
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div className="rounded-lg border border-green-500/20 bg-green-500/5 p-4">
                  <div className="text-xs text-gray-400">合规项</div>
                  <div className="mt-2 text-2xl font-bold text-green-400">{summary.compliant}</div>
                </div>
                <div className="rounded-lg border border-red-500/20 bg-red-500/5 p-4">
                  <div className="text-xs text-gray-400">不合规项</div>
                  <div className="mt-2 text-2xl font-bold text-red-400">{summary.nonCompliant}</div>
                </div>
                <div className="rounded-lg border border-orange-500/20 bg-orange-500/5 p-4">
                  <div className="text-xs text-gray-400">高危项</div>
                  <div className="mt-2 text-2xl font-bold text-orange-400">{summary.critical}</div>
                </div>
                <div className="rounded-lg border border-cyan-500/20 bg-cyan-500/5 p-4">
                  <div className="text-xs text-gray-400">检查总数</div>
                  <div className="mt-2 text-2xl font-bold text-cyan-400">{summary.total}</div>
                </div>
              </div>
            </div>
          </div>

          <div className="rounded-lg border border-cyan-500/20 bg-[#16213e]/80 p-5">
            <div className="mb-4 text-sm font-semibold text-cyan-300">检查结果明细</div>
            <Table>
              <thead>
                <tr className="border-b border-cyan-500/20 text-left text-xs text-cyan-200/70">
                  <th className="px-2 py-2 font-medium">检查项</th>
                  <th className="px-2 py-2 font-medium">期望值</th>
                  <th className="px-2 py-2 font-medium">实际值</th>
                  <th className="px-2 py-2 font-medium">状态</th>
                  <th className="px-2 py-2 font-medium">严重级别</th>
                  <th className="px-2 py-2 font-medium">修复建议</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {results.map((r, i) => (
                  <tr key={i} className="hover:bg-white/5">
                    <td className="px-2 py-2 text-gray-300">{r.check_name}</td>
                    <td className="px-2 py-2 text-gray-400">{r.expected_value}</td>
                    <td className="px-2 py-2 text-gray-400">{r.actual_value}</td>
                    <td className="px-2 py-2">
                      <Badge variant={getCheckStatusTag(r.status).variant}>{getCheckStatusTag(r.status).label}</Badge>
                    </td>
                    <td className="px-2 py-2">
                      <Badge variant={getSeverityTag(r.severity).variant}>{getSeverityTag(r.severity).label}</Badge>
                    </td>
                    <td className="px-2 py-2 text-gray-400">{r.remediation}</td>
                  </tr>
                ))}
              </tbody>
            </Table>
          </div>
        </div>
      )}
    </div>
  );
}
