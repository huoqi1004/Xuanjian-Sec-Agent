import { useState, useEffect, useRef } from 'react';
import { Table, Card, Typography, Button, Input, Select, Space, Tag, Progress, Row, Col, Statistic, Tabs, Modal, Form, DatePicker, message, Drawer, Badge, Tooltip, Timeline, Alert } from 'antd';
import { PlusOutlined, SearchOutlined, BugOutlined, WarningOutlined, ReloadOutlined, CheckCircleOutlined, ClockCircleOutlined, FileTextOutlined, RocketOutlined, FilterOutlined, EyeOutlined, EditOutlined, DeleteOutlined, SafetyOutlined } from '@ant-design/icons';
import * as echarts from 'echarts';

const { Title, Text } = Typography;
const { Option } = Select;
const { Search } = Input;
const { TabPane } = Tabs;
const { RangePicker } = DatePicker;

const API_BASE = 'http://localhost:8001/api/v1/security';

function Vulnerabilities() {
  const [vulnerabilities, setVulnerabilities] = useState([]);
  const [loading, setLoading] = useState(false);
  const [searchText, setSearchText] = useState('');
  const [severityFilter, setSeverityFilter] = useState('all');
  const [statusFilter, setStatusFilter] = useState('all');
  const [selectedVuln, setSelectedVuln] = useState(null);
  const [detailVisible, setDetailVisible] = useState(false);
  const [addModalVisible, setAddModalVisible] = useState(false);
  const [form] = Form.useForm();
  const chartRef = useRef(null);

  const mockData = [
    { key: '1', id: 'VULN-2026-001', name: 'CVE-2023-45678', description: 'Apache Log4j远程代码执行漏洞', severity: 'critical', status: 'unfixed', asset: 'Web服务器', cvss: 9.8, discovered: '2026-03-04 10:00:00', dueDate: '2026-03-15', type: 'Web漏洞', affected: 'Log4j 2.17.0' },
    { key: '2', id: 'VULN-2026-002', name: 'CVE-2023-12345', description: 'MySQL 8.0.30权限绕过漏洞', severity: 'high', status: 'fixing', asset: '数据库服务器', cvss: 6.5, discovered: '2026-03-04 09:30:00', dueDate: '2026-03-10', type: '数据库漏洞', affected: 'MySQL 8.0.30' },
    { key: '3', id: 'VULN-2026-003', name: 'CVE-2023-98765', description: 'Nginx 1.24.0信息泄露漏洞', severity: 'low', status: 'fixed', asset: 'Web服务器', cvss: 3.1, discovered: '2026-03-03 16:00:00', dueDate: '2026-03-05', type: 'Web漏洞', affected: 'Nginx 1.24.0' },
    { key: '4', id: 'VULN-2026-004', name: 'CVE-2023-65432', description: 'Windows Server 2019远程桌面漏洞', severity: 'critical', status: 'unfixed', asset: '文件服务器', cvss: 8.9, discovered: '2026-03-02 14:00:00', dueDate: '2026-03-12', type: '系统漏洞', affected: 'Windows Server 2019' },
    { key: '5', id: 'VULN-2026-005', name: 'CVE-2023-24678', description: 'OpenSSH 8.8缓冲区溢出漏洞', severity: 'high', status: 'fixed', asset: 'Linux服务器', cvss: 7.5, discovered: '2026-03-01 11:00:00', dueDate: '2026-03-03', type: '系统漏洞', affected: 'OpenSSH 8.8' },
    { key: '6', id: 'VULN-2026-006', name: 'CVE-2024-1111', description: 'Spring Framework远程代码执行', severity: 'critical', status: 'unfixed', asset: '应用服务器', cvss: 10.0, discovered: '2026-03-04 15:00:00', dueDate: '2026-03-08', type: '应用漏洞', affected: 'Spring Framework 6.0' },
    { key: '7', id: 'VULN-2026-007', name: 'CVE-2024-2222', description: 'Redis未授权访问漏洞', severity: 'high', status: 'fixing', asset: '缓存服务器', cvss: 8.2, discovered: '2026-03-04 12:00:00', dueDate: '2026-03-09', type: '应用漏洞', affected: 'Redis 7.0' },
  ];

  useEffect(() => {
    loadVulnerabilities();
    initCharts();
  }, []);

  useEffect(() => {
    if (vulnerabilities.length > 0) {
      initCharts();
    }
  }, [vulnerabilities]);

  const loadVulnerabilities = async () => {
    setLoading(true);
    try {
      const response = await fetch(`${API_BASE}/vulnerabilities`);
      const data = await response.json();
      setVulnerabilities(data.vulnerabilities || mockData);
    } catch (err) {
      setVulnerabilities(mockData);
    } finally {
      setLoading(false);
    }
  };

  const initCharts = () => {
    setTimeout(() => {
      const severityChart = echarts.init(document.getElementById('vuln-severity-chart'));
      const severityData = [
        { value: vulnerabilities.filter(v => v.severity === 'critical').length, name: '严重', itemStyle: { color: '#ff4d4f' } },
        { value: vulnerabilities.filter(v => v.severity === 'high').length, name: '高危', itemStyle: { color: '#fa8c16' } },
        { value: vulnerabilities.filter(v => v.severity === 'medium').length, name: '中危', itemStyle: { color: '#faad14' } },
        { value: vulnerabilities.filter(v => v.severity === 'low').length, name: '低危', itemStyle: { color: '#52c41a' } },
      ];
      severityChart.setOption({
        tooltip: { trigger: 'item' },
        series: [{
          type: 'pie',
          radius: ['40%', '70%'],
          data: severityData,
          label: { show: true, formatter: '{b}: {c}' }
        }]
      });

      const trendChart = echarts.init(document.getElementById('vuln-trend-chart'));
      trendChart.setOption({
        tooltip: { trigger: 'axis' },
        xAxis: { type: 'category', data: ['周一', '周二', '周三', '周四', '周五', '周六', '周日'] },
        yAxis: { type: 'value' },
        series: [{
          type: 'line',
          data: [5, 8, 3, 12, 6, 4, 7],
          smooth: true,
          areaStyle: { color: 'rgba(24,144,255,0.2)' },
          itemStyle: { color: '#1890ff' }
        }]
      });
    }, 100);
  };

  const getSeverityConfig = (severity) => {
    const config = {
      critical: { color: 'red', text: '严重', icon: <WarningOutlined /> },
      high: { color: 'orange', text: '高危', icon: <BugOutlined /> },
      medium: { color: 'gold', text: '中危', icon: <WarningOutlined /> },
      low: { color: 'green', text: '低危', icon: <SafetyOutlined /> }
    };
    return config[severity] || config.low;
  };

  const getStatusConfig = (status) => {
    const config = {
      unfixed: { color: 'red', text: '未修复' },
      fixing: { color: 'processing', text: '修复中' },
      fixed: { color: 'success', text: '已修复' },
      ignored: { color: 'default', text: '已忽略' }
    };
    return config[status] || config.unfixed;
  };

  const getCVSSColor = (cvss) => {
    if (cvss >= 9.0) return '#ff4d4f';
    if (cvss >= 7.0) return '#fa8c16';
    if (cvss >= 4.0) return '#faad14';
    return '#52c41a';
  };

  const filteredData = vulnerabilities.filter(v => {
    const matchSearch = !searchText || v.name.toLowerCase().includes(searchText.toLowerCase()) || v.description.toLowerCase().includes(searchText.toLowerCase());
    const matchSeverity = severityFilter === 'all' || v.severity === severityFilter;
    const matchStatus = statusFilter === 'all' || v.status === statusFilter;
    return matchSearch && matchSeverity && matchStatus;
  });

  const columns = [
    { title: '漏洞ID', dataIndex: 'id', key: 'id', width: 130, render: (id) => <Text copyable>{id}</Text> },
    { title: 'CVE编号', dataIndex: 'name', key: 'name', render: (name) => <Text strong>{name}</Text> },
    { title: '描述', dataIndex: 'description', key: 'description', ellipsis: true },
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
      title: 'CVSS', 
      dataIndex: 'cvss', 
      key: 'cvss', 
      width: 100,
      render: (cvss) => (
        <Tooltip title={`CVSS评分: ${cvss}`}>
          <Progress 
            type="circle" 
            percent={cvss * 10} 
            width={50}
            strokeColor={getCVSSColor(cvss)}
            format={() => cvss}
          />
        </Tooltip>
      )
    },
    { 
      title: '状态', 
      dataIndex: 'status', 
      key: 'status', 
      width: 100,
      render: (status) => {
        const config = getStatusConfig(status);
        return <Badge status={config.color === 'red' ? 'error' : config.color === 'processing' ? 'processing' : 'success'} text={config.text} />;
      }
    },
    { title: '受影响资产', dataIndex: 'asset', key: 'asset', width: 120 },
    { title: '发现时间', dataIndex: 'discovered', key: 'discovered', width: 160 },
    { title: '截止日期', dataIndex: 'dueDate', key: 'dueDate', width: 110 },
    {
      title: '操作',
      key: 'action',
      width: 120,
      render: (_, record) => (
        <Space>
          <Tooltip title="查看详情">
            <Button size="small" icon={<EyeOutlined />} onClick={() => { setSelectedVuln(record); setDetailVisible(true); }} />
          </Tooltip>
          <Tooltip title="创建工单">
            <Button size="small" type="primary" icon={<FileTextOutlined />} />
          </Tooltip>
        </Space>
      )
    }
  ];

  const stats = {
    total: vulnerabilities.length,
    critical: vulnerabilities.filter(v => v.severity === 'critical').length,
    high: vulnerabilities.filter(v => v.severity === 'high').length,
    unfixed: vulnerabilities.filter(v => v.status === 'unfixed').length,
    fixing: vulnerabilities.filter(v => v.status === 'fixing').length,
    fixed: vulnerabilities.filter(v => v.status === 'fixed').length,
  };

  return (
    <div style={{ padding: 24, background: '#f0f2f5', minHeight: '100vh' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24 }}>
        <Title level={2} style={{ margin: 0 }}>
          <BugOutlined style={{ color: '#fa8c16', marginRight: 8 }} />
          漏洞管理
        </Title>
        <Space>
          <Button icon={<ReloadOutlined />} onClick={loadVulnerabilities}>刷新</Button>
          <Button type="primary" icon={<PlusOutlined />} onClick={() => setAddModalVisible(true)}>手动添加</Button>
        </Space>
      </div>

      <Row gutter={[16, 16]} style={{ marginBottom: 24 }}>
        <Col xs={24} sm={12} md={6}>
          <Card hoverable>
            <Statistic title="漏洞总数" value={stats.total} prefix={<BugOutlined style={{ color: '#1890ff' }} />} />
          </Card>
        </Col>
        <Col xs={24} sm={12} md={6}>
          <Card hoverable style={{ borderLeft: '4px solid #ff4d4f' }}>
            <Statistic title="严重漏洞" value={stats.critical} prefix={<WarningOutlined style={{ color: '#ff4d4f' }} />} valueStyle={{ color: '#ff4d4f' }} />
          </Card>
        </Col>
        <Col xs={24} sm={12} md={6}>
          <Card hoverable style={{ borderLeft: '4px solid #fa8c16' }}>
            <Statistic title="待修复" value={stats.unfixed} prefix={<ClockCircleOutlined style={{ color: '#fa8c16' }} />} valueStyle={{ color: '#fa8c16' }} />
          </Card>
        </Col>
        <Col xs={24} sm={12} md={6}>
          <Card hoverable style={{ borderLeft: '4px solid #52c41a' }}>
            <Statistic title="已修复" value={stats.fixed} prefix={<CheckCircleOutlined style={{ color: '#52c41a' }} />} valueStyle={{ color: '#52c41a' }} />
          </Card>
        </Col>
      </Row>

      <Row gutter={[16, 16]} style={{ marginBottom: 24 }}>
        <Col xs={24} md={12}>
          <Card title="漏洞等级分布" size="small">
            <div id="vuln-severity-chart" style={{ height: 200 }}></div>
          </Card>
        </Col>
        <Col xs={24} md={12}>
          <Card title="漏洞发现趋势" size="small">
            <div id="vuln-trend-chart" style={{ height: 200 }}></div>
          </Card>
        </Col>
      </Row>

      <Card>
        <Tabs defaultActiveKey="all">
          <TabPane tab={<span><BugOutlined />全部 ({stats.total})</span>} key="all" />
          <TabPane tab={<span><WarningOutlined />严重 ({stats.critical})</span>} key="critical" />
          <TabPane tab={<span><ClockCircleOutlined />待修复 ({stats.unfixed})</span>} key="unfixed" />
          <TabPane tab={<span><RocketOutlined />修复中 ({stats.fixing})</span>} key="fixing" />
          <TabPane tab={<span><CheckCircleOutlined />已修复 ({stats.fixed})</span>} key="fixed" />
        </Tabs>

        <Space style={{ marginBottom: 16 }} size="middle">
          <Search placeholder="搜索漏洞..." allowClear style={{ width: 250 }} onSearch={setSearchText} />
          <Select value={severityFilter} onChange={setSeverityFilter} style={{ width: 120 }}>
            <Option value="all">全部等级</Option>
            <Option value="critical">严重</Option>
            <Option value="high">高危</Option>
            <Option value="medium">中危</Option>
            <Option value="low">低危</Option>
          </Select>
          <Select value={statusFilter} onChange={setStatusFilter} style={{ width: 120 }}>
            <Option value="all">全部状态</Option>
            <Option value="unfixed">未修复</Option>
            <Option value="fixing">修复中</Option>
            <Option value="fixed">已修复</Option>
          </Select>
        </Space>

        <Table 
          columns={columns} 
          dataSource={filteredData} 
          loading={loading}
          rowKey="key"
          pagination={{ pageSize: 10, showSizeChanger: true, showTotal: (total) => `共 ${total} 条` }}
        />
      </Card>

      <Drawer
        title="漏洞详情"
        placement="right"
        width={600}
        onClose={() => setDetailVisible(false)}
        open={detailVisible}
      >
        {selectedVuln && (
          <>
            <Card size="small" style={{ marginBottom: 16 }}>
              <Row gutter={16}>
                <Col span={12}>
                  <Statistic title="CVSS评分" value={selectedVuln.cvss} suffix="/10" />
                </Col>
                <Col span={12}>
                  <Statistic title="漏洞类型" value={selectedVuln.type} />
                </Col>
              </Row>
            </Card>
            <Card size="small" title="基本信息" style={{ marginBottom: 16 }}>
              <p><Text strong>CVE编号:</Text> {selectedVuln.name}</p>
              <p><Text strong>描述:</Text> {selectedVuln.description}</p>
              <p><Text strong>受影响组件:</Text> {selectedVuln.affected}</p>
              <p><Text strong>受影响资产:</Text> {selectedVuln.asset}</p>
              <p><Text strong>发现时间:</Text> {selectedVuln.discovered}</p>
              <p><Text strong>修复截止:</Text> {selectedVuln.dueDate}</p>
            </Card>
            <Card size="small" title="修复建议" style={{ marginBottom: 16 }}>
              <Alert
                message="建议立即修复"
                description={`该漏洞CVSS评分为${selectedVuln.cvss}，属于${getSeverityConfig(selectedVuln.severity).text}漏洞。建议尽快进行修复。`}
                type={selectedVuln.severity === 'critical' ? 'error' : 'warning'}
                showIcon
              />
              <Timeline style={{ marginTop: 16 }}>
                <Timeline.Item color="green">1. 评估漏洞影响范围</Timeline.Item>
                <Timeline.Item color="green">2. 应用官方补丁</Timeline.Item>
                <Timeline.Item color="green">3. 验证修复效果</Timeline.Item>
                <Timeline.Item color="green">4. 更新漏洞状态</Timeline.Item>
              </Timeline>
            </Card>
            <Space style={{ width: '100%', justifyContent: 'flex-end' }}>
              <Button icon={<EyeOutlined />}>查看完整报告</Button>
              <Button type="primary" icon={<FileTextOutlined />}>创建修复工单</Button>
            </Space>
          </>
        )}
      </Drawer>

      <Modal
        title="添加漏洞"
        open={addModalVisible}
        onCancel={() => setAddModalVisible(false)}
        footer={null}
      >
        <Form form={form} layout="vertical">
          <Form.Item name="name" label="CVE编号" rules={[{ required: true }]}>
            <Input placeholder="例如: CVE-2024-1234" />
          </Form.Item>
          <Form.Item name="description" label="描述" rules={[{ required: true }]}>
            <Input.TextArea rows={3} />
          </Form.Item>
          <Form.Item name="severity" label="严重程度" rules={[{ required: true }]}>
            <Select>
              <Option value="critical">严重</Option>
              <Option value="high">高危</Option>
              <Option value="medium">中危</Option>
              <Option value="low">低危</Option>
            </Select>
          </Form.Item>
          <Form.Item name="asset" label="受影响资产">
            <Input placeholder="例如: Web服务器" />
          </Form.Item>
          <Form.Item>
            <Space style={{ width: '100%', justifyContent: 'flex-end' }}>
              <Button onClick={() => setAddModalVisible(false)}>取消</Button>
              <Button type="primary" onClick={() => { message.success('漏洞添加成功'); setAddModalVisible(false); }}>确认添加</Button>
            </Space>
          </Form.Item>
        </Form>
      </Modal>
    </div>
  );
}

export default Vulnerabilities;
