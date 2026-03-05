import { useState } from 'react';
import { Card, Typography, Form, Input, Button, Table, Tag, Space, Spin, Alert, Descriptions, Divider, Tabs, Row, Col, Progress, Timeline, Collapse, Modal } from 'antd';
import { BugOutlined, UploadOutlined, FileSearchOutlined, ApiOutlined, ClockCircleOutlined } from '@ant-design/icons';

const { Title, Text, Paragraph } = Typography;
const { TabPane } = Tabs;
const { Panel } = Collapse;

const API_BASE = 'http://localhost:8001/api/v1/security';

function CapeSandbox() {
  const [form] = Form.useForm();
  const [loading, setLoading] = useState(false);
  const [analyzing, setAnalyzing] = useState(false);
  const [tasks, setTasks] = useState([]);
  const [currentTask, setCurrentTask] = useState(null);
  const [report, setReport] = useState(null);
  const [error, setError] = useState(null);
  const [activeTab, setActiveTab] = useState('submit');

  const handleSubmitFile = async (values) => {
    setLoading(true);
    setError(null);
    
    try {
      const response = await fetch(`${API_BASE}/cape/submit`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          file_hash: values.file_hash,
          options: values.options || {}
        })
      });
      
      if (!response.ok) throw new Error('提交失败');
      
      const data = await response.json();
      setCurrentTask(data);
      Modal.success({ title: '提交成功', content: `任务ID: ${data.task_id}` });
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleGetReport = async (taskId) => {
    setAnalyzing(true);
    setError(null);
    
    try {
      const response = await fetch(`${API_BASE}/cape/report/${taskId}`);
      if (!response.ok) throw new Error('获取报告失败');
      
      const data = await response.json();
      setReport(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setAnalyzing(false);
    }
  };

  const handleGetTasks = async () => {
    setLoading(true);
    try {
      const response = await fetch(`${API_BASE}/cape/tasks`);
      if (!response.ok) throw new Error('获取任务列表失败');
      
      const data = await response.json();
      setTasks(data.tasks || []);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const getStatusTag = (status) => {
    const statusMap = {
      'pending': { color: 'default', text: '等待中' },
      'running': { color: 'processing', text: '分析中' },
      'completed': { color: 'success', text: '已完成' },
      'failed': { color: 'error', text: '失败' }
    };
    const config = statusMap[status] || { color: 'default', text: status };
    return <Tag color={config.color}>{config.text}</Tag>;
  };

  const getSeverityColor = (severity) => {
    const colors = {
      'high': 'red',
      'medium': 'orange',
      'low': 'green',
      'info': 'blue'
    };
    return colors[severity] || 'default';
  };

  const taskColumns = [
    { title: '任务ID', dataIndex: 'task_id', key: 'task_id', width: 100 },
    { title: '文件名', dataIndex: 'filename', key: 'filename', ellipsis: true },
    { 
      title: '状态', 
      dataIndex: 'status', 
      key: 'status',
      render: (status) => getStatusTag(status)
    },
    { 
      title: '提交时间', 
      dataIndex: 'submitted_at', 
      key: 'submitted_at',
      render: (text) => text ? new Date(text).toLocaleString() : '-'
    },
    {
      title: '操作',
      key: 'action',
      render: (_, record) => (
        <Space>
          <Button 
            type="link" 
            size="small"
            icon={<FileSearchOutlined />}
            onClick={() => handleGetReport(record.task_id)}
          >
            查看报告
          </Button>
        </Space>
      )
    }
  ];

  const renderReportSummary = () => {
    if (!report) return null;
    
    return (
      <Card title="分析摘要" style={{ marginBottom: 16 }}>
        <Row gutter={16}>
          <Col span={6}>
            <Card size="small">
              <div style={{ textAlign: 'center' }}>
                <Progress 
                  type="circle" 
                  percent={report.summary?.malicious_score || 0} 
                  strokeColor={report.summary?.malicious_score > 70 ? '#ff4d4f' : '#52c41a'}
                />
                <div style={{ marginTop: 8 }}>恶意评分</div>
              </div>
            </Card>
          </Col>
          <Col span={6}>
            <Card size="small">
              <div style={{ textAlign: 'center' }}>
                <Title level={2} style={{ margin: 0, color: '#1890ff' }}>
                  {report.behaviors?.length || 0}
                </Title>
                <div>行为事件</div>
              </div>
            </Card>
          </Col>
          <Col span={6}>
            <Card size="small">
              <div style={{ textAlign: 'center' }}>
                <Title level={2} style={{ margin: 0, color: '#ff4d4f' }}>
                  {report.network?.dns?.length || 0}
                </Title>
                <div>DNS请求</div>
              </div>
            </Card>
          </Col>
          <Col span={6}>
            <Card size="small">
              <div style={{ textAlign: 'center' }}>
                <Title level={2} style={{ margin: 0, color: '#faad14' }}>
                  {report.network?.http?.length || 0}
                </Title>
                <div>HTTP请求</div>
              </div>
            </Card>
          </Col>
        </Row>
      </Card>
    );
  };

  const renderBehaviors = () => {
    if (!report?.behaviors) return null;
    
    return (
      <Card title="行为分析" style={{ marginBottom: 16 }}>
        <Table 
          dataSource={report.behaviors.map((b, idx) => ({ ...b, key: idx }))}
          columns={[
            { title: '类别', dataIndex: 'category', key: 'category', width: 120 },
            { title: '行为', dataIndex: 'action', key: 'action', width: 150 },
            { 
              title: '详情', 
              dataIndex: 'details', 
              key: 'details',
              ellipsis: true
            },
            {
              title: '严重程度',
              dataIndex: 'severity',
              key: 'severity',
              width: 100,
              render: (severity) => (
                <Tag color={getSeverityColor(severity)}>{severity}</Tag>
              )
            }
          ]}
          pagination={{ pageSize: 10 }}
          size="small"
        />
      </Card>
    );
  };

  const renderNetworkActivity = () => {
    if (!report?.network) return null;
    
    return (
      <Card title="网络活动" style={{ marginBottom: 16 }}>
        <Tabs defaultActiveKey="dns">
          <TabPane tab="DNS请求" key="dns">
            <Table 
              dataSource={(report.network.dns || []).map((d, idx) => ({ ...d, key: idx }))}
              columns={[
                { title: '域名', dataIndex: 'domain', key: 'domain' },
                { title: 'IP地址', dataIndex: 'ip', key: 'ip' },
                { title: '类型', dataIndex: 'type', key: 'type', width: 80 }
              ]}
              pagination={{ pageSize: 10 }}
              size="small"
            />
          </TabPane>
          <TabPane tab="HTTP请求" key="http">
            <Table 
              dataSource={(report.network.http || []).map((h, idx) => ({ ...h, key: idx }))}
              columns={[
                { title: '方法', dataIndex: 'method', key: 'method', width: 80 },
                { title: 'URI', dataIndex: 'uri', key: 'uri', ellipsis: true },
                { title: '状态码', dataIndex: 'status', key: 'status', width: 80 }
              ]}
              pagination={{ pageSize: 10 }}
              size="small"
            />
          </TabPane>
          <TabPane tab="网络连接" key="connections">
            <Table 
              dataSource={(report.network.connections || []).map((c, idx) => ({ ...c, key: idx }))}
              columns={[
                { title: '协议', dataIndex: 'protocol', key: 'protocol', width: 80 },
                { title: '目标IP', dataIndex: 'dst_ip', key: 'dst_ip' },
                { title: '目标端口', dataIndex: 'dst_port', key: 'dst_port', width: 100 },
                { title: '状态', dataIndex: 'state', key: 'state', width: 100 }
              ]}
              pagination={{ pageSize: 10 }}
              size="small"
            />
          </TabPane>
        </Tabs>
      </Card>
    );
  };

  const renderSignatures = () => {
    if (!report?.signatures) return null;
    
    return (
      <Card title="检测签名" style={{ marginBottom: 16 }}>
        <Collapse>
          {report.signatures.map((sig, idx) => (
            <Panel 
              header={
                <Space>
                  <Tag color={getSeverityColor(sig.severity)}>{sig.severity}</Tag>
                  <span>{sig.name}</span>
                  <Tag>{sig.category}</Tag>
                </Space>
              }
              key={idx}
            >
              <Descriptions size="small" column={1}>
                <Descriptions.Item label="描述">{sig.description}</Descriptions.Item>
                <Descriptions.Item label="置信度">{sig.confidence}%</Descriptions.Item>
                {sig.markdown && (
                  <Descriptions.Item label="详情">
                    <Paragraph style={{ marginBottom: 0, whiteSpace: 'pre-wrap' }}>
                      {sig.markdown}
                    </Paragraph>
                  </Descriptions.Item>
                )}
              </Descriptions>
            </Panel>
          ))}
        </Collapse>
      </Card>
    );
  };

  return (
    <div style={{ padding: 24 }}>
      <Title level={2}>
        <BugOutlined /> CAPE沙箱分析
      </Title>
      
      <Card style={{ marginBottom: 24 }}>
        <Tabs activeKey={activeTab} onChange={setActiveTab}>
          <TabPane 
            tab={
              <span>
                <UploadOutlined /> 提交样本
              </span>
            } 
            key="submit"
          >
            <Form form={form} layout="vertical" onFinish={handleSubmitFile} style={{ maxWidth: 600, marginTop: 16 }}>
              <Form.Item 
                name="file_hash" 
                label="文件哈希 (MD5/SHA1/SHA256)" 
                rules={[{ required: true, message: '请输入文件哈希' }]}
              >
                <Input placeholder="输入文件哈希值进行分析" />
              </Form.Item>
              <Form.Item>
                <Space>
                  <Button type="primary" htmlType="submit" loading={loading} icon={<ApiOutlined />}>
                    提交分析
                  </Button>
                  <Button onClick={() => form.resetFields()}>
                    重置
                  </Button>
                </Space>
              </Form.Item>
            </Form>
          </TabPane>
          
          <TabPane 
            tab={
              <span>
                <ClockCircleOutlined /> 任务列表
              </span>
            } 
            key="tasks"
          >
            <div style={{ marginBottom: 16, marginTop: 16 }}>
              <Button type="primary" onClick={handleGetTasks} loading={loading}>
                刷新任务列表
              </Button>
            </div>
            <Table 
              columns={taskColumns}
              dataSource={tasks}
              rowKey="task_id"
              pagination={{ pageSize: 10 }}
            />
          </TabPane>
        </Tabs>
      </Card>
      
      {error && <Alert message="错误" description={error} type="error" showIcon style={{ marginBottom: 24 }} />}
      
      <Spin spinning={analyzing}>
        {report && (
          <>
            {renderReportSummary()}
            {renderBehaviors()}
            {renderNetworkActivity()}
            {renderSignatures()}
          </>
        )}
      </Spin>
    </div>
  );
}

export default CapeSandbox;
