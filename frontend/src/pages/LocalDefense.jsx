import { useState, useEffect, useRef } from 'react';
import { Card, Typography, Button, Space, Table, Tag, Row, Col, Statistic, Switch, Progress, Timeline, Modal, Input, Alert, List, Badge, Tooltip, message, Divider } from 'antd';
import { SecurityScanOutlined, DesktopOutlined, LockOutlined, UnlockOutlined, ReloadOutlined, AlertOutlined, WarningOutlined, CheckCircleOutlined, ClockCircleOutlined, WifiOutlined, ThunderboltOutlined, SettingOutlined, PlayCircleOutlined, StopOutlined, ScanOutlined } from '@ant-design/icons';
import * as echarts from 'echarts';

const { Title, Text } = Typography;
const { Search } = Input;

const API_BASE = 'http://localhost:8001/api/v1/local-defense';

function LocalDefense() {
  const [loading, setLoading] = useState(false);
  const [networkInfo, setNetworkInfo] = useState(null);
  const [blockedIPs, setBlockedIPs] = useState([]);
  const [threats, setThreats] = useState([]);
  const [stats, setStats] = useState(null);
  const [config, setConfig] = useState(null);
  const [monitoring, setMonitoring] = useState(false);
  const [scanResults, setScanResults] = useState([]);
  const [blockModalVisible, setBlockModalVisible] = useState(false);
  const [blockIP, setBlockIP] = useState('');
  const [blockReason, setBlockReason] = useState('');
  const chartRef = useRef(null);

  useEffect(() => {
    loadData();
  }, []);

  useEffect(() => {
    if (stats) {
      initChart();
    }
  }, [stats]);

  const loadData = async () => {
    setLoading(true);
    try {
      const [infoRes, blockedRes, threatsRes, statsRes, configRes, statusRes] = await Promise.all([
        fetch(`${API_BASE}/network/info`).then(r => r.json()).catch(() => null),
        fetch(`${API_BASE}/blocked-ips`).then(r => r.json()).catch(() => ({ blocked_ips: [] })),
        fetch(`${API_BASE}/threats`).then(r => r.json()).catch(() => ({ threats: [] })),
        fetch(`${API_BASE}/stats`).then(r => r.json()).catch(() => null),
        fetch(`${API_BASE}/config`).then(r => r.json()).catch(() => null),
        fetch(`${API_BASE}/status`).then(r => r.json()).catch(() => null)
      ]);

      setNetworkInfo(infoRes);
      setBlockedIPs(blockedRes?.blocked_ips || []);
      setThreats(threatsRes?.threats || []);
      setStats(statsRes);
      setConfig(configRes);
      setMonitoring(statusRes?.monitoring || false);
    } catch (err) {
      console.error('加载数据失败:', err);
    } finally {
      setLoading(false);
    }
  };

  const initChart = () => {
    setTimeout(() => {
      const chart = echarts.init(document.getElementById('threat-chart'));
      if (stats?.severity_breakdown) {
        chart.setOption({
          tooltip: { trigger: 'item' },
          series: [{
            type: 'pie',
            radius: ['40%', '70%'],
            data: [
              { value: stats.severity_breakdown.critical || 0, name: '严重', itemStyle: { color: '#ff4d4f' } },
              { value: stats.severity_breakdown.high || 0, name: '高危', itemStyle: { color: '#fa8c16' } },
              { value: stats.severity_breakdown.medium || 0, name: '中危', itemStyle: { color: '#faad14' } },
              { value: stats.severity_breakdown.low || 0, name: '低危', itemStyle: { color: '#52c41a' } }
            ]
          }]
        });
      }
    }, 100);
  };

  const handleQuickScan = async () => {
    setLoading(true);
    try {
      const res = await fetch(`${API_BASE}/network/scan`).then(r => r.json());
      setScanResults(res.results || []);
      message.success(`扫描完成，发现 ${res.results?.length || 0} 个在线主机`);
    } catch (err) {
      message.error('扫描失败');
    } finally {
      setLoading(false);
    }
  };

  const handleBlockIP = async () => {
    if (!blockIP) {
      message.error('请输入IP地址');
      return;
    }

    try {
      await fetch(`${API_BASE}/block-ip`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip: blockIP, reason: blockReason || '手动封禁', duration: 86400 })
      });
      message.success(`IP ${blockIP} 已封禁`);
      setBlockModalVisible(false);
      setBlockIP('');
      setBlockReason('');
      loadData();
    } catch (err) {
      message.error('封禁失败');
    }
  };

  const handleUnblockIP = async (ip) => {
    try {
      await fetch(`${API_BASE}/block-ip/${ip}`, { method: 'DELETE' });
      message.success(`IP ${ip} 已解除封禁`);
      loadData();
    } catch (err) {
      message.error('解除封禁失败');
    }
  };

  const handleToggleMonitoring = async () => {
    try {
      if (monitoring) {
        await fetch(`${API_BASE}/monitoring/stop`, { method: 'POST' });
        message.success('监控已停止');
      } else {
        await fetch(`${API_BASE}/monitoring/start`, { method: 'POST' });
        message.success('监控已启动');
      }
      setMonitoring(!monitoring);
    } catch (err) {
      message.error('操作失败');
    }
  };

  const handleToggleAutoResponse = async () => {
    try {
      await fetch(`${API_BASE}/config`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ auto_response: !config?.auto_response_enabled })
      });
      message.success(`自动响应已${!config?.auto_response_enabled ? '启用' : '禁用'}`);
      loadData();
    } catch (err) {
      message.error('操作失败');
    }
  };

  const columns = [
    { title: 'IP地址', dataIndex: 'ip', key: 'ip', render: (ip) => <Text copyable>{ip}</Text> },
    { title: '原因', dataIndex: 'reason', key: 'reason', ellipsis: true },
    { title: '封禁时间', dataIndex: 'created_at', key: 'created_at', render: (t) => t ? new Date(t).toLocaleString() : '-' },
    { title: '过期时间', dataIndex: 'expires_at', key: 'expires_at', render: (t) => t ? new Date(t).toLocaleString() : '永久' },
    {
      title: '操作',
      key: 'action',
      render: (_, record) => (
        <Button size="small" danger icon={<UnlockOutlined />} onClick={() => handleUnblockIP(record.ip)}>
          解除封禁
        </Button>
      )
    }
  ];

  const threatColumns = [
    { title: '时间', dataIndex: 'timestamp', key: 'timestamp', render: (t) => t ? new Date(t).toLocaleString() : '-' },
    { title: '类型', dataIndex: 'type', key: 'type' },
    { title: '来源IP', dataIndex: 'source_ip', key: 'source_ip', render: (ip) => <Text copyable>{ip}</Text> },
    { title: '描述', dataIndex: 'description', key: 'description', ellipsis: true },
    {
      title: '严重程度',
      dataIndex: 'severity',
      key: 'severity',
      render: (s) => {
        const colors = { critical: 'red', high: 'orange', medium: 'gold', low: 'green' };
        return <Tag color={colors[s] || 'default'}>{s}</Tag>;
      }
    }
  ];

  return (
    <div style={{ padding: 24, background: '#f0f2f5', minHeight: '100vh' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24 }}>
        <Title level={2} style={{ margin: 0 }}>
          <SecurityScanOutlined style={{ color: '#1890ff', marginRight: 8 }} />
          本地防御系统
        </Title>
        <Space>
          <Button
            type={monitoring ? 'primary' : 'default'}
            icon={monitoring ? <StopOutlined /> : <PlayCircleOutlined />}
            onClick={handleToggleMonitoring}
          >
            {monitoring ? '停止监控' : '启动监控'}
          </Button>
          <Button icon={<ReloadOutlined />} onClick={loadData}>刷新</Button>
        </Space>
      </div>

      <Row gutter={[16, 16]} style={{ marginBottom: 24 }}>
        <Col xs={24} sm={12} md={6}>
          <Card hoverable>
            <Statistic
              title="本机IP"
              value={stats?.local_ip || '未知'}
              prefix={<DesktopOutlined style={{ color: '#1890ff' }} />}
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} md={6}>
          <Card hoverable>
            <Statistic
              title="封禁IP数"
              value={stats?.blocked_ips || 0}
              prefix={<LockOutlined style={{ color: '#ff4d4f' }} />}
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} md={6}>
          <Card hoverable>
            <Statistic
              title="威胁事件(24h)"
              value={stats?.threats_24h || 0}
              prefix={<WarningOutlined style={{ color: '#fa8c16' }} />}
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} md={6}>
          <Card hoverable>
            <Statistic
              title="防火墙状态"
              value={stats?.firewall_available ? '可用' : '不可用'}
              prefix={stats?.firewall_available ? <CheckCircleOutlined style={{ color: '#52c41a' }} /> : <WarningOutlined style={{ color: '#ff4d4f' }} />}
            />
          </Card>
        </Col>
      </Row>

      <Row gutter={[16, 16]} style={{ marginBottom: 24 }}>
        <Col xs={24} lg={12}>
          <Card
            title={
              <Space>
                <WifiOutlined />
                <span>网络信息</span>
              </Space>
            }
            extra={
              <Button icon={<ScanOutlined />} onClick={handleQuickScan} loading={loading}>
                快速扫描
              </Button>
            }
          >
            {networkInfo?.interfaces?.map((iface, idx) => (
              <div key={idx} style={{ marginBottom: 8, padding: 8, background: '#f5f5f5', borderRadius: 4 }}>
                <Text strong>{iface.name}</Text>
                <Text style={{ marginLeft: 16 }}>{iface.ip}</Text>
                <Tag color={iface.type === 'wireless' ? 'blue' : 'green'} style={{ marginLeft: 8 }}>{iface.type}</Tag>
              </div>
            ))}
            <Divider />
            <Text type="secondary">网络段: {networkInfo?.network_segments?.map(s => s.cidr).join(', ')}</Text>
          </Card>
        </Col>
        <Col xs={24} lg={12}>
          <Card
            title={
              <Space>
                <ThunderboltOutlined />
                <span>威胁分布</span>
              </Space>
            }
          >
            <div id="threat-chart" style={{ height: 200 }}></div>
          </Card>
        </Col>
      </Row>

      <Row gutter={[16, 16]} style={{ marginBottom: 24 }}>
        <Col xs={24}>
          <Card
            title={
              <Space>
                <LockOutlined />
                <span>IP封禁管理</span>
                <Tag color="red">{blockedIPs.length}</Tag>
              </Space>
            }
            extra={
              <Button type="primary" icon={<LockOutlined />} onClick={() => setBlockModalVisible(true)}>
                手动封禁
              </Button>
            }
          >
            <Table
              columns={columns}
              dataSource={blockedIPs}
              rowKey="rule_id"
              pagination={{ pageSize: 5 }}
              size="small"
            />
          </Card>
        </Col>
      </Row>

      <Row gutter={[16, 16]} style={{ marginBottom: 24 }}>
        <Col xs={24}>
          <Card
            title={
              <Space>
                <AlertOutlined />
                <span>威胁事件</span>
              </Space>
            }
          >
            <Table
              columns={threatColumns}
              dataSource={threats.slice(0, 10)}
              rowKey="id"
              pagination={{ pageSize: 5 }}
              size="small"
            />
          </Card>
        </Col>
      </Row>

      <Row gutter={[16, 16]}>
        <Col xs={24}>
          <Card
            title={
              <Space>
                <SettingOutlined />
                <span>防御配置</span>
              </Space>
            }
          >
            <Row gutter={[16, 16]}>
              <Col xs={24} md={8}>
                <Card size="small">
                  <Space>
                    <Switch checked={config?.auto_response_enabled} onChange={handleToggleAutoResponse} />
                    <Text>自动响应</Text>
                  </Space>
                  <Text type="secondary" style={{ display: 'block', marginTop: 8 }}>
                    自动封禁检测到的恶意IP
                  </Text>
                </Card>
              </Col>
              <Col xs={24} md={8}>
                <Card size="small">
                  <Space>
                    <Switch checked={monitoring} onChange={handleToggleMonitoring} />
                    <Text>实时监控</Text>
                  </Space>
                  <Text type="secondary" style={{ display: 'block', marginTop: 8 }}>
                    监控网络变化和威胁事件
                  </Text>
                </Card>
              </Col>
              <Col xs={24} md={8}>
                <Card size="small">
                  <Space>
                    <Badge status={stats?.firewall_available ? 'success' : 'error'} />
                    <Text>Windows防火墙</Text>
                  </Space>
                  <Text type="secondary" style={{ display: 'block', marginTop: 8 }}>
                    {stats?.firewall_available ? '已连接' : '不可用'}
                  </Text>
                </Card>
              </Col>
            </Row>
          </Card>
        </Col>
      </Row>

      {scanResults.length > 0 && (
        <Card title="扫描结果" style={{ marginTop: 16 }}>
          <List
            size="small"
            dataSource={scanResults}
            renderItem={item => (
              <List.Item>
                <Text>{item.ip}</Text>
                <Tag>{item.status}</Tag>
              </List.Item>
            )}
          />
        </Card>
      )}

      <Modal
        title="手动封禁IP"
        open={blockModalVisible}
        onCancel={() => setBlockModalVisible(false)}
        onOk={handleBlockIP}
        okText="确认封禁"
        okButtonProps={{ danger: true }}
      >
        <Input
          placeholder="输入IP地址"
          value={blockIP}
          onChange={(e) => setBlockIP(e.target.value)}
          style={{ marginBottom: 16 }}
        />
        <Input
          placeholder="封禁原因"
          value={blockReason}
          onChange={(e) => setBlockReason(e.target.value)}
        />
      </Modal>
    </div>
  );
}

export default LocalDefense;
