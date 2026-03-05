import { useState, useEffect } from 'react';
import { Card, Typography, Form, Input, Select, Button, Table, Tag, Space, Spin, Alert, Descriptions, Divider, Progress, Modal, List } from 'antd';
import { BugOutlined, PlayCircleOutlined, EyeOutlined, ReloadOutlined } from '@ant-design/icons';

const { Title, Text } = Typography;
const { Option } = Select;

const API_BASE = 'http://localhost:8001/api/v1/security';

function NessusScan() {
  const [form] = Form.useForm();
  const [loading, setLoading] = useState(false);
  const [scans, setScans] = useState([]);
  const [scanResult, setScanResult] = useState(null);
  const [error, setError] = useState(null);
  const [modalVisible, setModalVisible] = useState(false);
  const [selectedScan, setSelectedScan] = useState(null);

  useEffect(() => {
    fetchScans();
  }, []);

  const fetchScans = async () => {
    setLoading(true);
    try {
      const response = await fetch(`${API_BASE}/nessus/scans`);
      if (!response.ok) throw new Error('获取扫描列表失败');
      const data = await response.json();
      setScans(data.scans || []);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const createScan = async (values) => {
    setLoading(true);
    setError(null);
    
    try {
      const response = await fetch(`${API_BASE}/nessus/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(values)
      });
      
      if (!response.ok) throw new Error('创建扫描失败');
      
      const data = await response.json();
      Modal.success({ title: '扫描创建成功', content: `扫描ID: ${data.scan?.id}` });
      fetchScans();
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const launchScan = async (scanId) => {
    setLoading(true);
    try {
      const response = await fetch(`${API_BASE}/nessus/scan/${scanId}/launch`, {
        method: 'POST'
      });
      if (!response.ok) throw new Error('启动扫描失败');
      Modal.success({ title: '扫描已启动' });
      fetchScans();
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const getScanResults = async (scanId) => {
    setLoading(true);
    try {
      const response = await fetch(`${API_BASE}/nessus/scan/${scanId}/results`);
      if (!response.ok) throw new Error('获取结果失败');
      const data = await response.json();
      setScanResult(data);
      setModalVisible(true);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const scanColumns = [
    { title: 'ID', dataIndex: 'id', key: 'id' },
    { title: '名称', dataIndex: 'name', key: 'name' },
    { 
      title: '状态', 
      dataIndex: 'status', 
      key: 'status',
      render: (status) => {
        const color = status === 'completed' ? 'green' : status === 'running' ? 'blue' : 'default';
        return <Tag color={color}>{status}</Tag>;
      }
    },
    { title: '所有者', dataIndex: 'owner', key: 'owner' },
    { 
      title: '创建时间', 
      dataIndex: 'creation_date', 
      key: 'creation_date',
      render: (ts) => ts ? new Date(ts * 1000).toLocaleString() : '-'
    },
    {
      title: '操作',
      key: 'action',
      render: (_, record) => (
        <Space>
          <Button size="small" icon={<PlayCircleOutlined />} onClick={() => launchScan(record.id)}>
            启动
          </Button>
          <Button size="small" icon={<EyeOutlined />} onClick={() => getScanResults(record.id)}>
            查看结果
          </Button>
        </Space>
      )
    }
  ];

  const vulnColumns = [
    { title: '插件ID', dataIndex: 'plugin_id', key: 'plugin_id' },
    { title: '名称', dataIndex: 'plugin_name', key: 'plugin_name', ellipsis: true },
    { 
      title: '严重程度', 
      dataIndex: 'severity', 
      key: 'severity',
      render: (sev) => {
        const colors = { 4: 'red', 3: 'orange', 2: 'gold', 1: 'blue' };
        const labels = { 4: '严重', 3: '高危', 2: '中危', 1: '低危' };
        return <Tag color={colors[sev]}>{labels[sev] || sev}</Tag>;
      }
    },
    { title: '主机', dataIndex: 'host', key: 'host' },
    { title: '端口', dataIndex: 'port', key: 'port' },
    { 
      title: 'CVSS', 
      dataIndex: 'cvss_base_score', 
      key: 'cvss_base_score',
      render: (score) => score ? <Progress percent={score * 10} size="small" /> : '-'
    }
  ];

  return (
    <div style={{ padding: 24 }}>
      <Title level={2}>
        <BugOutlined /> Nessus漏洞扫描
      </Title>
      
      <Card title="创建扫描任务" style={{ marginBottom: 24 }}>
        <Form form={form} layout="inline" onFinish={createScan}>
          <Form.Item name="name" label="扫描名称" rules={[{ required: true }]}>
            <Input placeholder="输入扫描名称" style={{ width: 200 }} />
          </Form.Item>
          <Form.Item name="target" label="目标" rules={[{ required: true }]}>
            <Input placeholder="192.168.1.0/24" style={{ width: 200 }} />
          </Form.Item>
          <Form.Item name="template" label="模板" initialValue="basic">
            <Select style={{ width: 150 }}>
              <Option value="basic">基础扫描</Option>
              <Option value="advanced">高级扫描</Option>
              <Option value="malware">恶意软件检测</Option>
            </Select>
          </Form.Item>
          <Form.Item>
            <Button type="primary" htmlType="submit" loading={loading} icon={<BugOutlined />}>
              创建扫描
            </Button>
          </Form.Item>
          <Form.Item>
            <Button icon={<ReloadOutlined />} onClick={fetchScans}>刷新列表</Button>
          </Form.Item>
        </Form>
      </Card>
      
      {error && <Alert message="错误" description={error} type="error" showIcon style={{ marginBottom: 24 }} />}
      
      <Card title="扫描任务列表">
        <Spin spinning={loading}>
          <Table columns={scanColumns} dataSource={scans} rowKey="id" />
        </Spin>
      </Card>
      
      <Modal
        title="漏洞扫描结果"
        open={modalVisible}
        onCancel={() => setModalVisible(false)}
        footer={null}
        width={1000}
      >
        {scanResult && (
          <>
            <Descriptions bordered column={4} style={{ marginBottom: 16 }}>
              <Descriptions.Item label="扫描ID">{scanResult.scan_id}</Descriptions.Item>
              <Descriptions.Item label="总漏洞数">{scanResult.summary?.total_vulnerabilities}</Descriptions.Item>
              <Descriptions.Item label="严重">
                <Tag color="red">{scanResult.summary?.critical}</Tag>
              </Descriptions.Item>
              <Descriptions.Item label="高危">
                <Tag color="orange">{scanResult.summary?.high}</Tag>
              </Descriptions.Item>
            </Descriptions>
            
            <Divider>严重漏洞</Divider>
            <Table 
              columns={vulnColumns} 
              dataSource={scanResult.vulnerabilities?.critical} 
              rowKey="plugin_id"
              size="small"
              pagination={false}
            />
            
            <Divider>高危漏洞</Divider>
            <Table 
              columns={vulnColumns} 
              dataSource={scanResult.vulnerabilities?.high} 
              rowKey="plugin_id"
              size="small"
              pagination={false}
            />
          </>
        )}
      </Modal>
    </div>
  );
}

export default NessusScan;