import { useState, useEffect, useCallback } from 'react';
import { Card, Typography, Table, Tag, Space, Button, Spin, Alert, Descriptions, Divider, Modal, Form, Input, InputNumber, Select, Statistic, Progress, Row, Col, Tabs, Badge, Tooltip, message, Popconfirm, Empty } from 'antd';
import { SafetyOutlined, StopOutlined, DeleteOutlined, BarChartOutlined, ReloadOutlined, PlusOutlined, ExclamationCircleOutlined, ClockCircleOutlined, GlobalOutlined, SecurityScanOutlined, ThunderboltOutlined, WarningOutlined } from '@ant-design/icons';
import * as echarts from 'echarts';

const { Title, Text } = Typography;
const { TabPane } = Tabs;
const { Option } = Select;

const API_BASE = 'http://localhost:8001/api/v1/security';

function WAFManagement() {
  const [form] = Form.useForm();
  const [loading, setLoading] = useState(false);
  const [status, setStatus] = useState(null);
  const [blockedIPs, setBlockedIPs] = useState([]);
  const [attackLogs, setAttackLogs] = useState([]);
  const [statistics, setStatistics] = useState(null);
  const [error, setError] = useState(null);
  const [blockModalVisible, setBlockModalVisible] = useState(false);
  const [autoRefresh, setAutoRefresh] = useState(false);
  const [activeTab, setActiveTab] = useState('overview');

  const fetchAll = useCallback(async () => {
    setLoading(true);
    try {
      const [statusRes, blockedRes, logsRes, statsRes] = await Promise.all([
        fetch(`${API_BASE}/waf/status`).then(r => r.json()).catch(() => null),
        fetch(`${API_BASE}/waf/blocked-ips`).then(r => r.json()).catch(() => ({ blocked_ips: [] })),
        fetch(`${API_BASE}/waf/attack-logs`).then(r => r.json()).catch(() => ({ logs: [] })),
        fetch(`${API_BASE}/waf/statistics`).then(r => r.json()).catch(() => null)
      ]);
      
      setStatus(statusRes);
      setBlockedIPs(blockedRes?.blocked_ips || []);
      setAttackLogs(logsRes?.logs || []);
      setStatistics(statsRes);
      setError(null);
    } catch (err) {
      setError('获取数据失败: ' + err.message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchAll();
  }, [fetchAll]);

  useEffect(() => {
    let interval;
    if (autoRefresh) {
      interval = setInterval(fetchAll, 10000);
    }
    return () => {
      if (interval) clearInterval(interval);
    };
  }, [autoRefresh, fetchAll]);

  useEffect(() => {
    if (statistics && activeTab === 'statistics') {
      initCharts();
    }
  }, [statistics, activeTab]);

  const initCharts = () => {
    const attackTypeChart = echarts.init(document.getElementById('attack-type-chart'));
    if (attackTypeChart && statistics?.attack_types) {
      const data = Object.entries(statistics.attack_types).map(([name, value]) => ({ name, value }));
      attackTypeChart.setOption({
        tooltip: { trigger: 'item', formatter: '{b}: {c} ({d}%)' },
        legend: { orient: 'vertical', right: 10, top: 'center' },
        series: [{
          type: 'pie',
          radius: ['40%', '70%'],
          avoidLabelOverlap: false,
          itemStyle: { borderRadius: 10, borderColor: '#fff', borderWidth: 2 },
          label: { show: false },
          emphasis: { label: { show: true, fontSize: 14, fontWeight: 'bold' } },
          labelLine: { show: false },
          data: data
        }]
      });
    }

    const timelineChart = echarts.init(document.getElementById('timeline-chart'));
    if (timelineChart && statistics?.timeline) {
      timelineChart.setOption({
        tooltip: { trigger: 'axis' },
        xAxis: { type: 'category', data: statistics.timeline.labels || [] },
        yAxis: { type: 'value' },
        series: [
          { name: '总请求', type: 'line', smooth: true, data: statistics.timeline.total || [], itemStyle: { color: '#1890ff' } },
          { name: '拦截', type: 'line', smooth: true, data: statistics.timeline.blocked || [], itemStyle: { color: '#ff4d4f' } }
        ]
      });
    }

    const handleResize = () => {
      attackTypeChart?.resize();
      timelineChart?.resize();
    };
    window.addEventListener('resize', handleResize);
    return () => window.removeEventListener('resize', handleResize);
  };

  const handleBlockIP = async (values) => {
    try {
      const response = await fetch(`${API_BASE}/waf/block-ip?ip=${values.ip}&duration=${values.duration || 3600}`, {
        method: 'POST'
      });
      if (response.ok) {
        message.success(`IP ${values.ip} 已成功封禁`);
        setBlockModalVisible(false);
        form.resetFields();
        fetchAll();
      } else {
        throw new Error('封禁失败');
      }
    } catch (err) {
      message.error('封禁失败: ' + err.message);
    }
  };

  const handleUnblockIP = async (ip) => {
    try {
      const response = await fetch(`${API_BASE}/waf/block-ip/${ip}`, {
        method: 'DELETE'
      });
      if (response.ok) {
        message.success(`IP ${ip} 已解封`);
        fetchAll();
      } else {
        throw new Error('解封失败');
      }
    } catch (err) {
      message.error('解封失败: ' + err.message);
    }
  };

  const getAttackTypeColor = (type) => {
    const colorMap = {
      'SQL注入': 'red',
      'XSS攻击': 'orange',
      '命令注入': 'magenta',
      '文件包含': 'volcano',
      'CSRF攻击': 'gold',
      '暴力破解': 'lime',
      '扫描探测': 'cyan',
      '恶意爬虫': 'blue',
      'DDoS攻击': 'purple',
      'WebShell': 'red'
    };
    return colorMap[type] || 'default';
  };

  const getSeverityBadge = (severity) => {
    const config = {
      high: { status: 'error', text: '高危' },
      medium: { status: 'warning', text: '中危' },
      low: { status: 'success', text: '低危' }
    };
    const c = config[severity] || { status: 'default', text: severity };
    return <Badge status={c.status} text={c.text} />;
  };

  const blockedIPColumns = [
    { 
      title: 'IP地址', 
      dataIndex: 'ip', 
      key: 'ip',
      render: (ip) => (
        <Space>
          <GlobalOutlined />
          <Text copyable={{ text: ip, tooltips: ['复制IP', '已复制'] }}>{ip}</Text>
        </Space>
      )
    },
    { 
      title: '封禁原因', 
      dataIndex: 'reason', 
      key: 'reason',
      render: (reason) => <Tag color="orange">{reason}</Tag>
    },
    { 
      title: '封禁时间', 
      dataIndex: 'blocked_at', 
      key: 'blocked_at',
      render: (text) => text ? new Date(text).toLocaleString() : '-'
    },
    { 
      title: '过期时间', 
      dataIndex: 'expires_at', 
      key: 'expires_at',
      render: (text) => {
        if (!text) return '永久';
        const expires = new Date(text);
        const now = new Date();
        const diff = expires - now;
        if (diff < 0) return <Tag color="default">已过期</Tag>;
        const hours = Math.floor(diff / 3600000);
        const mins = Math.floor((diff % 3600000) / 60000);
        return (
          <Tooltip title={expires.toLocaleString()}>
            <Space>
              <ClockCircleOutlined />
              {hours > 0 ? `${hours}小时${mins}分钟` : `${mins}分钟`}
            </Space>
          </Tooltip>
        );
      }
    },
    {
      title: '操作',
      key: 'action',
      width: 100,
      render: (_, record) => (
        <Popconfirm
          title="确认解封"
          description={`确定要解封 IP ${record.ip} 吗？`}
          onConfirm={() => handleUnblockIP(record.ip)}
          okText="确认"
          cancelText="取消"
        >
          <Button type="link" danger icon={<DeleteOutlined />}>解封</Button>
        </Popconfirm>
      )
    }
  ];

  const attackLogColumns = [
    { 
      title: '时间', 
      dataIndex: 'timestamp', 
      key: 'timestamp',
      width: 160,
      render: (text) => text ? new Date(text).toLocaleString() : '-'
    },
    { 
      title: '来源IP', 
      dataIndex: 'source_ip', 
      key: 'source_ip',
      render: (ip) => <Text copyable={{ text: ip, tooltips: ['复制', '已复制'] }}>{ip}</Text>
    },
    { 
      title: '目标', 
      dataIndex: 'target', 
      key: 'target',
      ellipsis: true
    },
    { 
      title: '攻击类型', 
      dataIndex: 'attack_type', 
      key: 'attack_type',
      render: (type) => <Tag color={getAttackTypeColor(type)}>{type}</Tag>
    },
    { 
      title: 'URL', 
      dataIndex: 'url', 
      key: 'url',
      ellipsis: true,
      width: 200,
      render: (url) => (
        <Tooltip title={url}>
          <Text style={{ maxWidth: 200 }} ellipsis>{url}</Text>
        </Tooltip>
      )
    },
    {
      title: '严重程度',
      dataIndex: 'severity',
      key: 'severity',
      width: 100,
      render: (severity) => getSeverityBadge(severity)
    },
    {
      title: '动作',
      dataIndex: 'action',
      key: 'action',
      width: 80,
      render: (action) => (
        <Tag color={action === 'blocked' ? 'red' : 'green'} icon={action === 'blocked' ? <StopOutlined /> : <SafetyOutlined />}>
          {action === 'blocked' ? '已拦截' : '已放行'}
        </Tag>
      )
    }
  ];

  const renderOverview = () => (
    <>
      <Row gutter={[16, 16]} style={{ marginBottom: 24 }}>
        <Col xs={24} sm={12} md={6}>
          <Card 
            hoverable 
            style={{ background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)', border: 'none' }}
          >
            <Statistic
              title={<span style={{ color: 'rgba(255,255,255,0.85)' }}>WAF状态</span>}
              value={status?.status === 'running' ? '运行中' : '已停止'}
              prefix={<SecurityScanOutlined style={{ color: '#fff' }} />}
              valueStyle={{ color: '#fff', fontWeight: 'bold' }}
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} md={6}>
          <Card hoverable>
            <Statistic
              title="今日总请求"
              value={status?.total_requests || 0}
              suffix="次"
              prefix={<ThunderboltOutlined style={{ color: '#1890ff' }} />}
            />
            <Progress percent={75} showInfo={false} strokeColor="#1890ff" size="small" style={{ marginTop: 8 }} />
          </Card>
        </Col>
        <Col xs={24} sm={12} md={6}>
          <Card hoverable>
            <Statistic
              title="拦截请求"
              value={status?.blocked_requests || 0}
              suffix="次"
              prefix={<StopOutlined style={{ color: '#ff4d4f' }} />}
              valueStyle={{ color: '#cf1322' }}
            />
            <Progress 
              percent={status?.total_requests ? Math.round((status.blocked_requests / status.total_requests) * 100) : 0} 
              showInfo={false} 
              strokeColor="#ff4d4f" 
              size="small" 
              style={{ marginTop: 8 }} 
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} md={6}>
          <Card hoverable>
            <Statistic
              title="活跃连接"
              value={status?.active_connections || 0}
              suffix="个"
              prefix={<GlobalOutlined style={{ color: '#52c41a' }} />}
              valueStyle={{ color: '#3f8600' }}
            />
            <Progress percent={60} showInfo={false} strokeColor="#52c41a" size="small" style={{ marginTop: 8 }} />
          </Card>
        </Col>
      </Row>

      <Row gutter={[16, 16]}>
        <Col xs={24} lg={12}>
          <Card 
            title={
              <Space>
                <StopOutlined />
                <span>封禁IP管理</span>
                <Badge count={blockedIPs.length} style={{ backgroundColor: '#ff4d4f' }} />
              </Space>
            }
            extra={
              <Space>
                <Button 
                  type="primary" 
                  icon={<PlusOutlined />} 
                  onClick={() => setBlockModalVisible(true)}
                >
                  添加封禁
                </Button>
              </Space>
            }
          >
            {blockedIPs.length > 0 ? (
              <Table 
                columns={blockedIPColumns} 
                dataSource={blockedIPs} 
                rowKey="ip"
                pagination={{ pageSize: 5, showSizeChanger: false }}
                size="small"
              />
            ) : (
              <Empty description="暂无封禁IP" image={Empty.PRESENTED_IMAGE_SIMPLE} />
            )}
          </Card>
        </Col>
        
        <Col xs={24} lg={12}>
          <Card 
            title={
              <Space>
                <WarningOutlined />
                <span>攻击日志</span>
                <Badge count={attackLogs.filter(l => l.action === 'blocked').length} style={{ backgroundColor: '#faad14' }} />
              </Space>
            }
            extra={
              <Button icon={<ReloadOutlined />} onClick={fetchAll} loading={loading}>
                刷新
              </Button>
            }
          >
            <Table 
              columns={attackLogColumns} 
              dataSource={attackLogs} 
              rowKey="id"
              pagination={{ pageSize: 5, showSizeChanger: true, showTotal: (total) => `共 ${total} 条` }}
              size="small"
              scroll={{ x: 900 }}
            />
          </Card>
        </Col>
      </Row>
    </>
  );

  const renderStatistics = () => {
    if (!statistics) {
      return <Empty description="暂无统计数据" />;
    }

    return (
      <Row gutter={[16, 16]}>
        <Col xs={24} md={12}>
          <Card title="攻击类型分布">
            <div id="attack-type-chart" style={{ height: 300 }}></div>
          </Card>
        </Col>
        <Col xs={24} md={12}>
          <Card title="请求趋势">
            <div id="timeline-chart" style={{ height: 300 }}></div>
          </Card>
        </Col>
        <Col xs={24}>
          <Card title="统计概览">
            <Descriptions bordered column={{ xs: 1, sm: 2, md: 4 }}>
              <Descriptions.Item label="时间范围">{statistics.time_range}</Descriptions.Item>
              <Descriptions.Item label="总请求数">
                <Text strong style={{ color: '#1890ff' }}>{statistics.total_requests?.toLocaleString()}</Text>
              </Descriptions.Item>
              <Descriptions.Item label="拦截请求">
                <Text strong style={{ color: '#ff4d4f' }}>{statistics.blocked_requests?.toLocaleString()}</Text>
              </Descriptions.Item>
              <Descriptions.Item label="拦截率">
                <Text strong style={{ color: '#faad14' }}>
                  {statistics.total_requests ? ((statistics.blocked_requests / statistics.total_requests) * 100).toFixed(2) : 0}%
                </Text>
              </Descriptions.Item>
            </Descriptions>
          </Card>
        </Col>
        <Col xs={24}>
          <Card title="攻击类型统计">
            <Row gutter={[16, 16]}>
              {Object.entries(statistics.attack_types || {}).map(([type, count]) => (
                <Col xs={12} sm={8} md={6} lg={4} key={type}>
                  <Card size="small" hoverable style={{ textAlign: 'center' }}>
                    <Statistic 
                      title={<Tag color={getAttackTypeColor(type)}>{type}</Tag>}
                      value={count} 
                      valueStyle={{ fontSize: 24 }}
                    />
                  </Card>
                </Col>
              ))}
            </Row>
          </Card>
        </Col>
      </Row>
    );
  };

  return (
    <div style={{ padding: 24, background: '#f0f2f5', minHeight: '100vh' }}>
      <div style={{ marginBottom: 24, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <Title level={2} style={{ margin: 0 }}>
          <SafetyOutlined style={{ color: '#1890ff' }} /> 雷池WAF管理
        </Title>
        <Space>
          <Button 
            type={autoRefresh ? 'primary' : 'default'}
            icon={<ReloadOutlined spin={autoRefresh} />}
            onClick={() => setAutoRefresh(!autoRefresh)}
          >
            {autoRefresh ? '自动刷新中' : '开启自动刷新'}
          </Button>
          <Button icon={<ReloadOutlined />} onClick={fetchAll} loading={loading}>
            手动刷新
          </Button>
        </Space>
      </div>
      
      {error && <Alert message="错误" description={error} type="error" showIcon style={{ marginBottom: 24 }} closable onClose={() => setError(null)} />}
      
      <Spin spinning={loading}>
        <Tabs 
          activeKey={activeTab} 
          onChange={setActiveTab}
          tabBarExtraContent={
            <Space>
              <Text type="secondary">
                <ClockCircleOutlined /> 最后更新: {new Date().toLocaleTimeString()}
              </Text>
            </Space>
          }
        >
          <TabPane 
            tab={<span><SecurityScanOutlined /> 概览</span>} 
            key="overview"
          >
            {renderOverview()}
          </TabPane>
          <TabPane 
            tab={<span><BarChartOutlined /> 统计分析</span>} 
            key="statistics"
          >
            {renderStatistics()}
          </TabPane>
        </Tabs>
      </Spin>

      <Modal
        title={
          <Space>
            <StopOutlined style={{ color: '#ff4d4f' }} />
            <span>添加IP封禁</span>
          </Space>
        }
        open={blockModalVisible}
        onCancel={() => {
          setBlockModalVisible(false);
          form.resetFields();
        }}
        footer={null}
        width={500}
      >
        <Form form={form} layout="vertical" onFinish={handleBlockIP} style={{ marginTop: 16 }}>
          <Form.Item 
            name="ip" 
            label="IP地址" 
            rules={[
              { required: true, message: '请输入IP地址' },
              { pattern: /^(\d{1,3}\.){3}\d{1,3}$/, message: '请输入有效的IP地址' }
            ]}
          >
            <Input placeholder="例如: 192.168.1.100" prefix={<GlobalOutlined />} />
          </Form.Item>
          <Form.Item 
            name="duration" 
            label="封禁时长（秒）" 
            initialValue={3600}
            rules={[{ required: true, message: '请输入封禁时长' }]}
          >
            <Select>
              <Option value={3600}>1小时</Option>
              <Option value={86400}>24小时</Option>
              <Option value={604800}>7天</Option>
              <Option value={2592000}>30天</Option>
              <Option value={-1}>永久</Option>
            </Select>
          </Form.Item>
          <Form.Item 
            name="reason" 
            label="封禁原因"
          >
            <Input placeholder="请输入封禁原因（可选）" />
          </Form.Item>
          <Form.Item style={{ marginBottom: 0, textAlign: 'right' }}>
            <Space>
              <Button onClick={() => {
                setBlockModalVisible(false);
                form.resetFields();
              }}>
                取消
              </Button>
              <Button type="primary" danger htmlType="submit" icon={<StopOutlined />}>
                确认封禁
              </Button>
            </Space>
          </Form.Item>
        </Form>
      </Modal>
    </div>
  );
}

export default WAFManagement;
