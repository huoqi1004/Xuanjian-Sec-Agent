import { useCallback, useMemo, useState } from 'react';
import {
  ReactFlow,
  Background,
  Controls,
  addEdge,
  useNodesState,
  useEdgesState,
  type OnConnect,
  type Node,
  type Edge,
  type OnNodesChange,
  type NodeTypes
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import type { PlaybookStep } from '@/api';

// ─── Step type constants ───────────────────────────────────────────────────────
const TYPE_CONDITION  = 'condition';
const TYPE_ACTION     = 'action';
const TYPE_NOTIFICATION = 'notification';
const TYPE_APPROVAL   = 'approval';
const TYPE_WAIT       = 'wait';

const ACTION_TYPES = [
  'firewall_block', 'account_lock', 'raise_alert', 'notify',
  'webhook', 'log_only', 'switch_acl_block', 'switch_acl_unblock',
  'cloud_sg_block', 'cloud_sg_unblock', 'siem_webhook'
];

// ─── Step type metadata ────────────────────────────────────────────────────────
const TYPE_META: Record<string, { label: string; color: string; bg: string }> = {
  [TYPE_CONDITION]:  { label: '条件判断', color: '#f59e0b', bg: 'rgba(245,158,11,0.12)'  },
  [TYPE_ACTION]:     { label: '动作',     color: '#10b981', bg: 'rgba(16,185,129,0.12)'  },
  [TYPE_NOTIFICATION]: { label: '通知',   color: '#6366f1', bg: 'rgba(99,102,241,0.12)'  },
  [TYPE_APPROVAL]:   { label: '审批',     color: '#ef4444', bg: 'rgba(239,68,68,0.12)'   },
  [TYPE_WAIT]:       { label: '等待',     color: '#8b5cf6', bg: 'rgba(139,92,246,0.12)'  }
};

const NODE_HEIGHT = 130;

// ─── Converters ────────────────────────────────────────────────────────────────

function stepToNode(step: PlaybookStep, index: number, selected = false): Node {
  const type     = step.type || TYPE_CONDITION;
  const meta     = TYPE_META[type] ?? TYPE_META[TYPE_CONDITION];
  const nodeId   = `n${index}`;
  return {
    id: nodeId,
    type: 'stepNode',
    position: { x: 320, y: index * NODE_HEIGHT },
    data: { step, index, type, label: meta.label, color: meta.color, bg: meta.bg, selected },
    selectable: true,
    draggable: true
  };
}

function stepsToNodes(steps: PlaybookStep[]): Node[] {
  return steps.map((s, i) => stepToNode(s, i));
}

function nodesToSteps(nodes: Node[]): PlaybookStep[] {
  const sorted = [...nodes].sort((a, b) => a.position.y - b.position.y);
  return sorted.map((n) => (n.data as { step: PlaybookStep }).step);
}

// ─── Custom Node ───────────────────────────────────────────────────────────────

function StepNode({ data }: { data: {
  step: PlaybookStep; type: string; label: string;
  color: string; bg: string; selected?: boolean;
}}) {
  return (
    <div
      data-testid={`step-node-${data.step.type}`}
      style={{
        background: data.bg,
        border: `2px solid ${data.color}`,
        borderRadius: 10,
        minWidth: 160,
        maxWidth: 220,
        padding: '8px 12px',
        boxShadow: data.selected ? `0 0 0 3px ${data.color}44` : '0 2px 8px rgba(0,0,0,0.3)'
      }}
    >
      {/* top handle */}
      <div data-handleid="top" data-handlepos="top"
        style={{ position: 'absolute', top: -5, left: '50%', marginLeft: -5,
          width: 10, height: 10, borderRadius: '50%', background: data.color, border: '2px solid #1e293b' }} />
      {/* bottom handle */}
      <div data-handleid="bottom" data-handlepos="bottom"
        style={{ position: 'absolute', bottom: -5, left: '50%', marginLeft: -5,
          width: 10, height: 10, borderRadius: '50%', background: data.color, border: '2px solid #1e293b' }} />
      {/* header */}
      <div className="flex items-center gap-2 mb-1.5">
        <span className="text-xs font-bold uppercase tracking-wider" style={{ color: data.color }}>
          {data.label}
        </span>
      </div>
      {/* body */}
      <div className="text-xs text-gray-300 space-y-0.5">
        {data.step.type === TYPE_CONDITION && (
          <>
            <div><span className="text-gray-500">字段：</span>{data.step.fact ?? '-'}</div>
            <div>
              <span className="text-gray-500">关系：</span>
              <span className="font-mono text-amber-400">{data.step.operator}</span>
              <span className="text-gray-500 ml-1">=</span>
              <span className="font-mono text-amber-300"> {data.step.value ?? '-'}</span>
            </div>
          </>
        )}
        {data.step.type === TYPE_ACTION && (
          <>
            <div className="font-mono text-green-400 text-[11px]">{data.step.action ?? '-'}</div>
            {data.step.name && <div className="text-gray-400 truncate">{data.step.name}</div>}
          </>
        )}
        {data.step.type === TYPE_NOTIFICATION && (
          <>
            <div><span className="text-gray-500">渠道：</span>{data.step.channel ?? 'all'}</div>
            {data.step.message && (
              <div className="text-gray-400 truncate" title={data.step.message}>{data.step.message}</div>
            )}
          </>
        )}
        {data.step.type === TYPE_APPROVAL && (
          <div className="font-medium text-red-300">{data.step.title ?? '等待审批'}</div>
        )}
        {data.step.type === TYPE_WAIT && (
          <div>
            <span className="text-gray-500">等待：</span>
            <span className="font-mono text-violet-400">{data.step.seconds ?? 0}s</span>
          </div>
        )}
      </div>
    </div>
  );
}

const customNodeTypes: NodeTypes = { stepNode: StepNode };

// ─── Canvas Component ─────────────────────────────────────────────────────────

interface Props {
  steps: PlaybookStep[];
  onChange: (steps: PlaybookStep[]) => void;
}

export default function PlaybookCanvas({ steps, onChange }: Props) {
  const [nodes, setNodes, onNodesChange] = useNodesState<Record<string, unknown>>(stepsToNodes(steps));
  const [edges, setEdges, onEdgesChange] = useEdgesState<Edge[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const selectedNode = useMemo(
    () => nodes.find((n) => n.id === selectedId) ?? null,
    [nodes, selectedId]
  );

  const handleConnect: OnConnect = useCallback(
    (p) => setEdges((eds) => addEdge({ ...p, animated: true, style: { stroke: '#475569', strokeWidth: 2 } }, eds)),
    [setEdges]
  );

  const notifySteps = useCallback(
    (next: Node[]) => { onChange(nodesToSteps(next)); },
    [onChange]
  );

  const onNodesChangeWithSync: OnNodesChange = useCallback(
    (changes) => {
      onNodesChange(changes, (next) => notifySteps(next));
    },
    [onNodesChange, notifySteps]
  );

  const addNode = (type: string, defaultStep: PlaybookStep) => {
    const lastY = nodes.length > 0 ? Math.max(...nodes.map((n) => n.position.y)) : 0;
    const newNode = stepToNode(defaultStep, nodes.length, false);
    newNode.position = { x: 320, y: lastY + NODE_HEIGHT };
    const next = [...nodes, newNode];
    setNodes(next);
    notifySteps(next);
  };

  const updateNodeStep = (nodeId: string, updatedStep: PlaybookStep) => {
    const next = nodes.map((n) =>
      n.id === nodeId ? { ...n, data: { ...n.data, step: updatedStep } } : n
    );
    setNodes(next);
    notifySteps(next);
  };

  const deleteSelected = () => {
    if (!selectedId) return;
    const next = nodes.filter((n) => n.id !== selectedId);
    setNodes(next);
    setSelectedId(null);
    notifySteps(next);
  };

  return (
    <div className="flex h-[480px] rounded-lg border border-cyan-500/20 overflow-hidden">
      {/* Left toolbar */}
      <div className="w-44 shrink-0 bg-[#0f172a] border-r border-white/5 p-3 flex flex-col gap-2">
        <div className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-1">节点类型</div>
        <ToolButton label="条件判断" color="#f59e0b" type={TYPE_CONDITION}
          onClick={() => addNode(TYPE_CONDITION, { type: TYPE_CONDITION, name: '条件判断', fact: '', operator: 'gt', value: 0 })} />
        <ToolButton label="动作"     color="#10b981" type={TYPE_ACTION}
          onClick={() => addNode(TYPE_ACTION, { type: TYPE_ACTION, name: '执行动作', action: 'firewall_block', params: {} })} />
        <ToolButton label="通知"     color="#6366f1" type={TYPE_NOTIFICATION}
          onClick={() => addNode(TYPE_NOTIFICATION, { type: TYPE_NOTIFICATION, name: '发送通知', channel: 'all', message: '' })} />
        <ToolButton label="审批"     color="#ef4444" type={TYPE_APPROVAL}
          onClick={() => addNode(TYPE_APPROVAL, { type: TYPE_APPROVAL, name: '人工审批', title: '请确认是否执行此操作' })} />
        <ToolButton label="等待"     color="#8b5cf6" type={TYPE_WAIT}
          onClick={() => addNode(TYPE_WAIT, { type: TYPE_WAIT, name: '等待', seconds: 10 })} />
        <div className="mt-auto text-[10px] text-gray-600 leading-4">
          点击节点选中 · 拖拽调整位置 · 连线自动生成
        </div>
      </div>

      {/* Center canvas */}
      <div className="flex-1 bg-[#0c1222]">
        <ReactFlow
          nodes={nodes}
          edges={edges}
          onNodesChange={onNodesChangeWithSync}
          onEdgesChange={onEdgesChange}
          onConnect={handleConnect}
          onNodeClick={(_, node) => setSelectedId(node.id)}
          onPaneClick={() => setSelectedId(null)}
          nodeTypes={customNodeTypes}
          fitView
          minZoom={0.3}
          maxZoom={2}
          defaultEdgeOptions={{ animated: true, style: { stroke: '#475569', strokeWidth: 2 } }}
        >
          <Background color="#1e293b" gap={20} size={1} />
          <Controls className="flex gap-1 [&>button]:bg-[#1e293b] [&>button]:border-white/10 [&>button]:text-gray-400" />
        </ReactFlow>
      </div>

      {/* Right property panel */}
      <PropertyPanel
        node={selectedNode as Node & { data: { step: PlaybookStep; type: string; color: string; label: string }} | null}
        onUpdate={(s) => { if (selectedId) updateNodeStep(selectedId, s); }}
        onDelete={deleteSelected}
      />
    </div>
  );
}

// ─── Toolbar button ────────────────────────────────────────────────────────────

function ToolButton({ label, color, type, onClick }: {
  label: string; color: string; type: string; onClick: () => void;
}) {
  return (
    <button type="button" onClick={onClick}
      className="flex items-center gap-2 rounded-md border border-white/10 px-3 py-2 text-xs text-gray-300 transition-colors hover:border-white/20 hover:bg-white/5">
      <span className="inline-block h-2.5 w-2.5 rounded-full shrink-0" style={{ background: color }} />
      <span className="font-medium">{label}</span>
      <span className="ml-auto text-[10px] text-gray-600 uppercase">{type}</span>
    </button>
  );
}

// ─── Property Panel ────────────────────────────────────────────────────────────

interface PropPanelProps {
  node: Node & { data: { step: PlaybookStep; type: string; color: string; label: string }} | null;
  onUpdate: (step: PlaybookStep) => void;
  onDelete: () => void;
}

function PropertyPanel({ node, onUpdate, onDelete }: PropPanelProps) {
  if (!node) {
    return (
      <div className="w-52 shrink-0 bg-[#0f172a] border-l border-white/5 p-4 flex items-center justify-center">
        <p className="text-center text-xs text-gray-600">点击画布中的节点<br />查看和编辑属性</p>
      </div>
    );
  }

  const { step, type, color } = node.data;
  const updateField = <K extends keyof PlaybookStep>(key: K, value: PlaybookStep[K]) => {
    onUpdate({ ...step, [key]: value });
  };

  return (
    <div className="w-56 shrink-0 bg-[#0f172a] border-l border-white/5 p-4 overflow-y-auto">
      <div className="flex items-center gap-2 mb-4">
        <span className="h-2.5 w-2.5 rounded-full shrink-0" style={{ background: color }} />
        <span className="text-xs font-semibold text-gray-300">{node.data.label}</span>
        <span className="ml-auto text-[10px] font-mono text-gray-600">{node.id}</span>
      </div>

      <Field label="节点名称">
        <input className={fieldCls} value={step.name ?? ''} placeholder="步骤名称"
          onChange={(e) => updateField('name', e.target.value)} />
      </Field>

      {type === TYPE_CONDITION && (
        <>
          <Field label="变量字段">
            <input className={fieldCls} value={step.fact ?? ''} placeholder="如: fail_count, severity"
              onChange={(e) => updateField('fact', e.target.value)} />
          </Field>
          <Field label="操作符">
            <select className={fieldCls} value={step.operator ?? 'gt'}
              onChange={(e) => updateField('operator', e.target.value)}>
              <option value="gt">&gt; 大于</option>
              <option value="gte">&ge; 大于等于</option>
              <option value="lt">&lt; 小于</option>
              <option value="lte">&le; 小于等于</option>
              <option value="eq">= 等于</option>
              <option value="neq">≠ 不等于</option>
            </select>
          </Field>
          <Field label="阈值">
            <input className={fieldCls} value={step.value ?? ''} placeholder="数值或字符串"
              onChange={(e) => {
                const v = e.target.value, num = Number(v);
                updateField('value', isNaN(num) ? v : num);
              }} />
          </Field>
        </>
      )}

      {type === TYPE_ACTION && (
        <>
          <Field label="动作类型">
            <select className={fieldCls} value={step.action ?? 'firewall_block'}
              onChange={(e) => updateField('action', e.target.value)}>
              {ACTION_TYPES.map((a) => <option key={a} value={a}>{a}</option>)}
            </select>
          </Field>
          <Field label="参数 (JSON)">
            <textarea className={`${fieldCls} resize-none font-mono text-xs`} rows={4}
              value={step.params ? JSON.stringify(step.params, null, 2) : '{}'}
              onChange={(e) => {
                try { updateField('params', JSON.parse(e.target.value)); } catch { /* ignore */ }
              }} />
          </Field>
          <div className="text-[10px] text-gray-500 leading-4">
            支持 <code className="font-mono text-cyan-400">{'{{字段}}'}</code> 引用事件字段
          </div>
        </>
      )}

      {type === TYPE_NOTIFICATION && (
        <>
          <Field label="通知渠道">
            <select className={fieldCls} value={step.channel ?? 'all'}
              onChange={(e) => updateField('channel', e.target.value)}>
              <option value="all">全部渠道</option>
              <option value="email">邮件</option>
              <option value="webhook">Webhook</option>
              <option value="siem">SIEM</option>
            </select>
          </Field>
          <Field label="通知内容">
            <textarea className={`${fieldCls} resize-none font-mono text-xs`} rows={3}
              value={step.message ?? ''}
              onChange={(e) => updateField('message', e.target.value)} />
          </Field>
        </>
      )}

      {type === TYPE_APPROVAL && (
        <Field label="审批提示">
          <textarea className={`${fieldCls} resize-none font-mono text-xs`} rows={3}
            value={step.title ?? ''}
            onChange={(e) => updateField('title', e.target.value)} />
        </Field>
      )}

      {type === TYPE_WAIT && (
        <Field label="等待时间（秒）">
          <input className={fieldCls} type="number" min={0} value={step.seconds ?? 0}
            onChange={(e) => updateField('seconds', Number(e.target.value))} />
        </Field>
      )}

      <div className="mt-4 pt-3 border-t border-white/5">
        <button type="button" onClick={onDelete}
          className="w-full rounded-md border border-red-500/30 bg-red-500/10 px-3 py-1.5 text-xs text-red-400 transition-colors hover:bg-red-500/20">
          删除此节点
        </button>
      </div>
    </div>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="mb-3">
      <label className="mb-1 block text-[11px] font-medium text-gray-500">{label}</label>
      {children}
    </div>
  );
}

const fieldCls =
  'w-full rounded-md border border-cyan-500/20 bg-[#1a2340] px-2.5 py-1.5 text-xs text-gray-300 outline-none transition-colors placeholder:text-gray-600 focus:border-cyan-500/60';
