import { useState, useEffect } from 'react';
import { Card, Typography, Form, Input, Button, Table, Tag, Space, Spin, Alert, Descriptions, Divider, Tabs, Row, Col, Statistic, DatePicker, Select, Progress, Badge, Modal } from 'antd';
import { FileSearchOutlined, SearchOutlined, BarChartOutlined, AlertOutlined, ClockCircleOutlined, DatabaseOutlined, LineChartOutlined } from '@ant-design/icons';

const { Title, Text, Paragraph } = Typography;
const { TabPane } = Tabs;
const { RangePicker } = DatePicker;
const { Option } = Select;

const API_BASE = 'http://localhost:8001/api/v1/security';

function ElkLogAnalysis() {
  const [form] = Form.useForm();
  const [loading, setLoading] = useState(false);
  const [logs, setLogs] = useState([]);
  const [statistics, setStatistics] = useState(null);
  const [alerts, setAlerts] = useState([]);
  const [error, setError] = useState(null);
  const [activeTab, setActiveTab] = useState('search');
  const [searchQuery, setSearchQuery] = useState('');

  useEffect(() => {
    fetchStatistics();
    fetchAlerts();
  }, []);

  const fetchStatistics = async () => {
    try {
      const response = await fetch(`${API_BASE}/elk/statistics`);
      if (response.ok) {
        const data = await response.json();
        setStatistics(data);
      }
    } catch (err) {
      console.error('获取统计失败:', err);
    }
  };

  const fetchAlerts = async () => {
    try {
      const response = await fetch(`${API_BASE}/elk/alerts`);
      if (response.ok) {
        const data = await response.json();
        setAlerts(data.alerts || []);
      }
    } catch (err) {
      console.error('获取告警失败:', err);
    }
  };

  const handleSearch = async (values) => {
    setLoading(true);
    setError(null);
    
    try {
      const params = new URLSearchParams();
      if (values.query) params.append('query', values.query);
      if (values.index) params.append('index', values.index);
      if (values.size) params.append('size', values.size);
      
      const response = await fetch(`${API_BASE}/elk/search?${params.toString()}`);
      if (!response.ok) throw new Error('搜索失败');
      
      const data = await response.json();
      setLogs(data.hits || []);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const getLevelColor = (level) => {
    const colors = {
      'error': 'red',
      'warning': 'orange',
      'info': 'blue',
      'debug': 'default'
    };
    return colors[level?.toLowerCase()] || 'default';
  };

  const getAlertSeverity = (severity) => {
    const colors = {
      'high': 'red',
      'medium': 'orange',
      'low': 'green'
    };
    return colors[severity] || 'default';
  };

  const logColumns = [
    {
      title: '时间',
      dataIndex: 'timestamp',
      key: 'timestamp',
      width: 180,
      render: (text) => text ? new Date(text).toLocaleString() : '-'
    },
    {
      title: '级别',
      dataIndex: 'level',
      key: 'level',
      width: 80,
      render: (level) => (
        <Tag color={getLevelColor(level)}>{level?.toUpperCase()}</Tag>
      )
    },
    {
      title: '来源',
      dataIndex: 'source',
      key: 'source',
      width: 120,
      ellipsis: true
    },
    {
      title: '主机',
      dataIndex: 'host',
      key: 'host',
      width: 120
    },
    {
      title: '消息',
      dataIndex: 'message',
      key: 'message',
      ellipsis: true
    },
    {
      title: '操作',
      key: 'action',
      width: 80,
      render: (_, record) => (
        <Button type="link" size="small" onClick={() => {
          Modal.info({
            title: '日志详情',
            width: 800,
            content: (
              <pre style={{ maxHeight: 400, overflow: 'auto' }}>
                {JSON.stringify(record, null, 2)}
              </pre>
            )
          });
        }}>
          详情
        </Button>
      )
    }
  ];

  const alertColumns = [
    {
      title: '时间',
      dataIndex: 'timestamp',
      key: 'timestamp',
      width: 180,
      render: (text) => text ? new Date(text).toLocaleString() : '-'
    },
    {
      title: '严重程度',
      dataIndex: 'severity',
      key: 'severity',
      width: 100,
      render: (severity) => (
        <Badge status={severity === 'high' ? 'error' : severity === 'medium' ? 'warning' : 'success'} text={severity} />
      )
    },
    {
      title: '规则名称',
      dataIndex: 'rule_name',
      key: 'rule_name',
      ellipsis: true
    },
    {
      title: '来源',
      dataIndex: 'source',
      key: 'source',
      width: 120
    },
    {
      title: '状态',
      dataIndex: 'status',
      key: 'status',
      width: 80,
      render: (status) => (
        <Tag color={status === 'open' ? 'red' : 'green'}>{status}</Tag>
      )
    }
  ];

  const renderStatistics = () => {
    if (!statistics) return null;
    
    return (
      <Row gutter={16} style={{ marginBottom: 24 }}>
        <Col span={6}>
          <Card>
            <Statistic
              title="总日志数"
              value={statistics.total_logs || 0}
              prefix={<DatabaseOutlined />}
              suffix="条"
            />
          </Card>
        </Col>
        <Col span={6}>
          <Card>
            <Statistic
              title="错误日志"
              value={statistics.error_count || 0}
              prefix={<AlertOutlined />}
              valueStyle={{ color: '#cf1322' }}
              suffix="条"
            />
          </Card>
        </Col>
        <Col span={6}>
          <Card>
            <Statistic
              title="警告日志"
              value={statistics.warning_count || 0}
              prefix={<AlertOutlined />}
              valueStyle={{ color: '#fa8c16' }}
              suffix="条"
            />
          </Card>
        </Col>
        <Col span={6}>
          <Card>
            <Statistic
              title="活跃告警"
              value={statistics.active_alerts || 0}
              prefix={<AlertOutlined />}
              valueStyle={{ color: '#cf1322' }}
              suffix="个"
            />
          </Card>
        </Col>
      </Row>
    );
  };

  const renderLogLevelChart = () => {
    if (!statistics?.log_levels) return null;
    
    return (
      <Card title="日志级别分布" style={{ marginBottom: 16 }}>
        <Row gutter={16}>
          {Object.entries(statistics.log_levels).map(([level, count]) => (
            <Col span={6} key={level}>
              <div style={{ textAlign: 'center', marginBottom: 8 }}>
                <Text strong>{level.toUpperCase()}</Text>
              </div>
              <Progress 
                percent={Math.round((count / (statistics.total_logs || 1)) * 100)} 
                strokeColor={getLevelColor(level)}
                format={() => count}
              />
            </Col>
          ))}
        </Row>
      </Card>
    );
  };

  const renderTopSources = () => {
    if (!statistics?.top_sources) return null;
    
    return (
      <Card title="Top 10 日志来源" style={{ marginBottom: 16 }}>
        <Table 
          dataSource={statistics.top_sources.map((s, idx) => ({ ...s, key: idx }))}
          columns={[
            { title: '排名', dataIndex: 'rank', key: 'rank', width: 60, render: (_, __, idx) => idx + 1 },
            { title: '来源', dataIndex: 'source', key: 'source' },
            { title: '日志数量', dataIndex: 'count', key: 'count', sorter: (a, b) => a.count - b.count }
          ]}
          pagination={false}
          size="small"
        />
      </Card>
    );
  };

  return (
    <div style={{ padding: 24 }}>
      <Title level={2}>
        <FileSearchOutlined /> ELK日志分析
      </Title>
      
      {renderStatistics()}
      
      <Card style={{ marginBottom: 24 }}>
        <Tabs activeKey={activeTab} onChange={setActiveTab}>
          <TabPane 
            tab={
              <span>
                <SearchOutlined /> 日志搜索
              </span>
            } 
            key="search"
          >
            <Form form={form} layout="inline" onFinish={handleSearch} style={{ marginTop: 16, marginBottom: 16 }}>
              <Form.Item name="query" label="查询语句">
                <Input placeholder="输入Lucene查询语法" style={{ width: 400 }} />
              </Form.Item>
              <Form.Item name="index" label="索引" initialValue="*">
                <Select style={{ width: 150 }}>
                  <Option value="*">所有索引</Option>
                  <Option value="security-*">安全日志</Option>
                  <Option value="syslog-*">系统日志</Option>
                  <Option value="nginx-*">Nginx日志</Option>
                </Select>
              </Form.Item>
              <Form.Item name="size" label="条数" initialValue={100}>
                <Select style={{ width: 100 }}>
                  <Option value={50}>50</Option>
                  <Option value={100}>100</Option>
                  <Option value={500}>500</Option>
                  <Option value={1000}>1000</Option>
                </Select>
              </Form.Item>
              <Form.Item>
                <Button type="primary" htmlType="submit" loading={loading} icon={<SearchOutlined />}>
                  搜索
                </Button>
              </Form.Item>
            </Form>
            
            {error && <Alert message="错误" description={error} type="error" showIcon style={{ marginBottom: 16 }} />}
            
            <Table 
              columns={logColumns}
              dataSource={logs.map((log, idx) => ({ ...log, key: idx }))}
              pagination={{ pageSize: 20 }}
              loading={loading}
              scroll={{ x: 1000 }}
            />
          </TabPane>
          
          <TabPane 
            tab={
              <span>
                <AlertOutlined /> 安全告警
              </span>
            } 
            key="alerts"
          >
            <div style={{ marginTop: 16 }}>
              <Table 
                columns={alertColumns}
                dataSource={alerts.map((alert, idx) => ({ ...alert, key: idx }))}
                pagination={{ pageSize: 20 }}
              />
            </div>
          </TabPane>
          
          <TabPane 
            tab={
              <span>
                <BarChartOutlined /> 统计分析
              </span>
            } 
            key="statistics"
          >
            <div style={{ marginTop: 16 }}>
              {renderLogLevelChart()}
              {renderTopSources()}
            </div>
          </TabPane>
        </Tabs>
      </Card>
    </div>
  );
}

export default ElkLogAnalysis;
