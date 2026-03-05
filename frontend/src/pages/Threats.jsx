import { useState, useEffect, useRef } from 'react';
import { Table, Card, Typography, Button, Input, Select, Space, Tag, Badge, Row, Col, Statistic, Progress, Timeline, Modal, Form, Tabs, Alert, Tooltip, message, Drawer, List, Avatar, Divider } from 'antd';
import { PlusOutlined, SearchOutlined, AlertOutlined, WarningOutlined, CheckCircleOutlined, CloseCircleOutlined, ThunderboltOutlined, EyeOutlined, SettingOutlined, ReloadOutlined, FilterOutlined, RobotOutlined, SafetyOutlined, ClockCircleOutlined, ArrowRightOutlined, BellOutlined } from '@ant-design/icons';
import * as echarts from 'echarts';

const { Title, Text } = Typography;
const { Option } = Select;
const { Search } = Input;
const { TabPane } = Tabs;

const API_BASE = 'http://localhost:8001/api/v1/security';

function Threats() {
  const [activeTab, setActiveTab] = useState('all');
  const [threats, setThreats] = useState([]);
  const [filteredThreats, setFilteredThreats] = useState([]);
  const [loading, setLoading] = useState(false);
  const [selectedThreat, setSelectedThreat] = useState(null);
  const [detailVisible, setDetailVisible] = useState(false);
  const [noiseReductionStats, setNoiseReductionStats] = useState({
    total: 1250,
    reduced: 1087,
    reducedRate: 86.9,
    high: 45,
    medium: 78,
    low: 40
  });
  const [autoProcessEnabled, setAutoProcessEnabled] = useState(true);
  const chartRef = useRef(null);

  useEffect(() => {
    loadThreats();
    initCharts();
  }, []);

  useEffect(() => {
    filterThreats();
  }, [threats, activeTab]);

  const loadThreats = async () => {
    setLoading(true);
    try {
      const response = await fetch(`${API_BASE}/threats`);
      const data = await response.json();
      setThreats(data.threats || getMockThreats());
    } catch (err) {
      setThreats(getMockThreats());
    } finally {
      setLoading(false);
    }
  };

  const getMockThreats = () => [
    { key: '1', id: 'TH-2026-001', name: 'SQL注入攻击', severity: 'high', status: 'processed', source: '外部', target: 'Web服务器', detected: '2026-03-04 10:00:00', handled: '2026-03-04 10:30:00', score: 85, noise_reduced: true, attack_type: 'Web攻击' },
    { key: '2', id: 'TH-2026-002', name: 'DDoS攻击', severity: 'critical', status: 'processing', source: '外部', target: '负载均衡器', detected: '2026-03-04 11:15:00', handled: null, score: 95, noise_reduced: false, attack_type: 'DDoS攻击' },
    { key: '3', id: 'TH-2026-003', name: '异常登录尝试', severity: 'medium', status: 'processed', source: '内部', target: '数据库服务器', detected: '2026-03-04 09:45:00', handled: '2026-03-04 10:00:00', score: 60, noise_reduced: true, attack_type: '暴力破解' },
    { key: '4', id: 'TH-2026-004', name: '恶意软件检测', severity: 'high', status: 'pending', source: '内部', target: '员工电脑', detected: '2026-03-04 14:30:00', handled: null, score: 78, noise_reduced: false, attack_type: '恶意软件' },
    { key: '5', id: 'TH-2026-005', name: '端口扫描', severity: 'low', status: 'processed', source: '外部', target: '网络边界', detected: '2026-03-04 08:15:00', handled: '2026-03-04 08:30:00', score: 35, noise_reduced: true, attack_type: '侦察' },
    { key: '6', id: 'TH-2026-006', name: 'XSS跨站脚本', severity: 'medium', status: 'processed', source: '外部', target: 'Web应用', detected: '2026-03-04 07:20:00', handled: '2026-03-04 07:45:00', score: 55, noise_reduced: true, attack_type: 'Web攻击' },
    { key: '7', id: 'TH-2026-007', name: '勒索软件警告', severity: 'critical', status: 'processing', source: '内部', target: '文件服务器', detected: '2026-03-04 15:00:00', handled: null, score: 98, noise_reduced: false, attack_type: '勒索软件' },
  ];

  const filterThreats = () => {
    let filtered = [...threats];
    if (activeTab === 'critical') {
      filtered = threats.filter(t => t.severity === 'critical');
    } else if (activeTab === 'high') {
      filtered = threats.filter(t => t.severity === 'high');
    } else if (activeTab === 'pending') {
      filtered = threats.filter(t => t.status === 'pending' || t.status === 'processing');
    } else if (activeTab === 'noise_reduced') {
      filtered = threats.filter(t => t.noise_reduced);
    }
    setFilteredThreats(filtered);
  };

  const initCharts = () => {
    setTimeout(() => {
      const chart = echarts.init(document.getElementById('threat-trend-chart'));
      chart.setOption({
        title: { text: '威胁趋势', left: 'center' },
        tooltip: { trigger: 'axis' },
        legend: { data: ['总告警', '降噪后', '高危'], bottom: 0 },
        xAxis: { type: 'category', data: ['00:00', '04:00', '08:00', '12:00', '16:00', '20:00'] },
        yAxis: { type: 'value' },
        series: [
          { name: '总告警', type: 'line', data: [320, 280, 450, 380, 290, 310], smooth: true, itemStyle: { color: '#ff4d4f' } },
          { name: '降噪后', type: 'line', data: [45, 38, 62, 52, 42, 48], smooth: true, itemStyle: { color: '#52c41a' } },
          { name: '高危', type: 'line', data: [12, 15, 18, 14, 10, 16], smooth: true, itemStyle: { color: '#faad14' } }
        ]
      });
    }, 100);
  };

  const getSeverityConfig = (severity) => {
    const config = {
      critical: { color: 'red', text: '严重', icon: <WarningOutlined /> },
      high: { color: 'orange', text: '高危', icon: <AlertOutlined /> },
      medium: { color: 'gold', text: '中危', icon: <WarningOutlined /> },
      low: { color: 'green', text: '低危', icon: <SafetyOutlined /> }
    };
    return config[severity] || config.low;
  };

  const getStatusConfig = (status) => {
    const config = {
      pending: { color: 'default', text: '待处理', icon: <ClockCircleOutlined /> },
      processing: { color: 'processing', text: '处理中', icon: <ReloadOutlined spin /> },
      processed: { color: 'success', text: '已处理', icon: <CheckCircleOutlined /> },
      closed: { color: 'default', text: '已关闭', icon: <CloseCircleOutlined /> }
    };
    return config[status] || config.pending;
  };

  const handleProcess = (threat) => {
    Modal.confirm({
      title: '处理威胁',
      icon: <RobotOutlined />,
      content: `确定要处理威胁 "${threat.name}" 吗？`,
      okText: '确认处理',
      cancelText: '取消',
      onOk: () => {
        message.success('已开始处理威胁');
        loadThreats();
      }
    });
  };

  const handleAutoBlock = (threat) => {
    Modal.confirm({
      title: '自动处置',
      icon: <ThunderboltOutlined />,
      content: `确定要对威胁源 "${threat.source}" 执行自动封禁吗？`,
      okText: '确认封禁',
      okButtonProps: { danger: true },
      onOk: () => {
        message.success('已执行自动封禁');
      }
    });
  };

  const columns = [
    {
      title: '威胁ID',
      dataIndex: 'id',
      key: 'id',
      width: 120,
      render: (id) => <Text copyable>{id}</Text>
    },
    {
      title: '威胁名称',
      dataIndex: 'name',
      key: 'name',
      render: (name, record) => (
        <Space>
          {record.noise_reduced && (
            <Tooltip title="AI降噪处理">
              <Badge status="success" />
            </Tooltip>
          )}
          <Text strong>{name}</Text>
        </Space>
      )
    },
    {
      title: '严重程度',
      dataIndex: 'severity',
      key: 'severity',
      width: 100,
      render: (severity) => {
        const config = getSeverityConfig(severity);
        return <Tag color={config.color} icon={config.icon}>{config.text}</Tag>;
      }
    },
    {
      title: '威胁评分',
      dataIndex: 'score',
      key: 'score',
      width: 100,
      render: (score) => (
        <Progress
          percent={score}
          size="small"
          strokeColor={score >= 80 ? '#ff4d4f' : score >= 60 ? '#faad14' : '#52c41a'}
          style={{ width: 80 }}
        />
      )
    },
    {
      title: '状态',
      dataIndex: 'status',
      key: 'status',
      width: 100,
      render: (status) => {
        const config = getStatusConfig(status);
        return <Badge status={config.color} text={config.text} icon={config.icon} />;
      }
    },
    {
      title: '来源',
      dataIndex: 'source',
      key: 'source',
      width: 80
    },
    {
      title: '目标',
      dataIndex: 'target',
      key: 'target',
      ellipsis: true
    },
    {
      title: '检测时间',
      dataIndex: 'detected',
      key: 'detected',
      width: 160
    },
    {
      title: '操作',
      key: 'action',
      width: 180,
      render: (_, record) => (
        <Space>
          <Tooltip title="查看详情">
            <Button size="small" icon={<EyeOutlined />} onClick={() => { setSelectedThreat(record); setDetailVisible(true); }} />
          </Tooltip>
          {autoProcessEnabled && (
            <Tooltip title="自动处置">
              <Button size="small" type="primary" danger icon={<ThunderboltOutlined />} onClick={() => handleAutoBlock(record)} />
            </Tooltip>
          )}
          <Tooltip title="处理">
            <Button size="small" type="primary" icon={<CheckCircleOutlined />} onClick={() => handleProcess(record)} />
          </Tooltip>
        </Space>
      )
    }
  ];

  return (
    <div style={{ padding: 24 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24 }}>
        <Title level={2} style={{ margin: 0 }}>
          <AlertOutlined style={{ color: '#1890ff', marginRight: 8 }} />
          威胁管理
        </Title>
        <Space>
          <Button
            type={autoProcessEnabled ? 'primary' : 'default'}
            icon={<RobotOutlined />}
            onClick={() => setAutoProcessEnabled(!autoProcessEnabled)}
          >
            自动处置 {autoProcessEnabled ? '已开启' : '已关闭'}
          </Button>
          <Button icon={<ReloadOutlined />} onClick={loadThreats}>刷新</Button>
        </Space>
      </div>

      <Row gutter={[16, 16]} style={{ marginBottom: 24 }}>
        <Col xs={24} sm={12} md={6}>
          <Card>
            <Statistic
              title="告警总量"
              value={noiseReductionStats.total}
              prefix={<BellOutlined style={{ color: '#1890ff' }} />}
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} md={6}>
          <Card>
            <Statistic
              title="降噪处理"
              value={noiseReductionStats.reduced}
              prefix={<FilterOutlined style={{ color: '#52c41a' }} />}
              suffix={`(${noiseReductionStats.reducedRate}%)`}
              valueStyle={{ color: '#52c41a' }}
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} md={6}>
          <Card>
            <Statistic
              title="待处理"
              value={noiseReductionStats.high + noiseReductionStats.medium}
              prefix={<WarningOutlined style={{ color: '#faad14' }} />}
              valueStyle={{ color: '#faad14' }}
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} md={6}>
          <Card>
            <Statistic
              title="严重威胁"
              value={noiseReductionStats.high}
              prefix={<WarningOutlined style={{ color: '#ff4d4f' }} />}
              valueStyle={{ color: '#ff4d4f' }}
            />
          </Card>
        </Col>
      </Row>

      <Card style={{ marginBottom: 24 }}>
        <div id="threat-trend-chart" style={{ height: 250 }}></div>
      </Card>

      <Card>
        <Tabs activeKey={activeTab} onChange={setActiveTab}>
          <TabPane tab={<span><AlertOutlined />全部威胁 ({threats.length})</span>} key="all" />
          <TabPane tab={<span><WarningOutlined />严重威胁 ({threats.filter(t => t.severity === 'critical').length})</span>} key="critical" />
          <TabPane tab={<span><AlertOutlined />高危威胁 ({threats.filter(t => t.severity === 'high').length})</span>} key="high" />
          <TabPane tab={<span><ClockCircleOutlined />待处理 ({threats.filter(t => t.status === 'pending' || t.status === 'processing').length})</span>} key="pending" />
          <TabPane tab={<span><FilterOutlined />已降噪 ({threats.filter(t => t.noise_reduced).length})</span>} key="noise_reduced" />
        </Tabs>

        <Table
          columns={columns}
          dataSource={filteredThreats}
          loading={loading}
          rowKey="key"
          pagination={{ pageSize: 10, showSizeChanger: true, showTotal: (total) => `共 ${total} 条` }}
        />
      </Card>

      <Drawer
        title="威胁详情"
        placement="right"
        width={600}
        onClose={() => setDetailVisible(false)}
        open={detailVisible}
      >
        {selectedThreat && (
          <>
            <Card size="small" style={{ marginBottom: 16 }}>
              <Row gutter={16}>
                <Col span={12}>
                  <Statistic title="威胁评分" value={selectedThreat.score} suffix="/100" />
                </Col>
                <Col span={12}>
                  <Statistic title="AI降噪" value={selectedThreat.noise_reduced ? '是' : '否'} />
                </Col>
              </Row>
            </Card>

            <Card size="small" title="基本信息" style={{ marginBottom: 16 }}>
              <p><Text strong>威胁ID:</Text> {selectedThreat.id}</p>
              <p><Text strong>威胁名称:</Text> {selectedThreat.name}</p>
              <p><Text strong>攻击类型:</Text> {selectedThreat.attack_type}</p>
              <p><Text strong>来源:</Text> {selectedThreat.source}</p>
              <p><Text strong>目标:</Text> {selectedThreat.target}</p>
              <p><Text strong>检测时间:</Text> {selectedThreat.detected}</p>
            </Card>

            <Card size="small" title="研判信息" style={{ marginBottom: 16 }}>
              <Text strong>AI自动研判结论:</Text>
              <Alert
                message="该威胁经过AI分析，判定为真实攻击事件，建议立即处理"
                type="warning"
                showIcon
                style={{ marginTop: 8 }}
              />
              <Divider />
              <Text strong>推荐处置方案:</Text>
              <List
                size="small"
                dataSource={['1. 封禁攻击源IP', '2. 阻断相关攻击链路', '3. 加固目标系统', '4. 创建修复工单']}
                renderItem={item => <List.Item>{item}</List.Item>}
              />
            </Card>

            <Space style={{ width: '100%', justifyContent: 'flex-end' }}>
              <Button icon={<EyeOutlined />}>查看完整日志</Button>
              <Button type="primary" danger icon={<ThunderboltOutlined />}>自动处置</Button>
              <Button type="primary" icon={<CheckCircleOutlined />}>确认处理</Button>
            </Space>
          </>
        )}
      </Drawer>
    </div>
  );
}

export default Threats;
