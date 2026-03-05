import { useState } from 'react';
import { Card, Typography, Form, Input, Select, Button, Table, Tag, Space, Spin, Alert, Descriptions, Divider } from 'antd';
import { ScanOutlined, DesktopOutlined, BugOutlined } from '@ant-design/icons';

const { Title, Text } = Typography;
const { Option } = Select;

const API_BASE = 'http://localhost:8001/api/v1/security';

function NmapScan() {
  const [form] = Form.useForm();
  const [loading, setLoading] = useState(false);
  const [scanResult, setScanResult] = useState(null);
  const [error, setError] = useState(null);
  const [activeTab, setActiveTab] = useState('network');

  const handleNetworkScan = async (values) => {
    setLoading(true);
    setError(null);
    setScanResult(null);
    
    try {
      const response = await fetch(`${API_BASE}/nmap/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(values)
      });
      
      if (!response.ok) throw new Error('扫描请求失败');
      
      const data = await response.json();
      setScanResult(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handlePortScan = async (target, port) => {
    setLoading(true);
    setError(null);
    
    try {
      const response = await fetch(`${API_BASE}/nmap/port/${target}/${port}`);
      if (!response.ok) throw new Error('端口扫描失败');
      
      const data = await response.json();
      setScanResult({ type: 'port', data });
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleOSScan = async (target) => {
    setLoading(true);
    setError(null);
    
    try {
      const response = await fetch(`${API_BASE}/nmap/os/${target}`);
      if (!response.ok) throw new Error('OS检测失败');
      
      const data = await response.json();
      setScanResult({ type: 'os', data });
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleVulnScan = async (target) => {
    setLoading(true);
    setError(null);
    
    try {
      const response = await fetch(`${API_BASE}/nmap/vuln/${target}`);
      if (!response.ok) throw new Error('漏洞扫描失败');
      
      const data = await response.json();
      setScanResult({ type: 'vuln', data });
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const hostColumns = [
    {
      title: 'IP地址',
      dataIndex: 'address',
      key: 'address',
      render: (text) => <Text strong>{text}</Text>
    },
    {
      title: '状态',
      dataIndex: 'status',
      key: 'status',
      render: (status) => (
        <Tag color={status === 'up' ? 'green' : 'red'}>
          {status === 'up' ? '在线' : '离线'}
        </Tag>
      )
    },
    {
      title: '主机名',
      dataIndex: 'hostname',
      key: 'hostname'
    },
    {
      title: '操作系统',
      dataIndex: 'os',
      key: 'os'
    },
    {
      title: '开放端口',
      dataIndex: 'ports',
      key: 'ports',
      render: (ports) => (
        <Space wrap>
          {ports?.slice(0, 5).map((p, idx) => (
            <Tag key={idx} color="blue">{p.port}/{p.service}</Tag>
          ))}
          {ports?.length > 5 && <Tag>+{ports.length - 5}</Tag>}
        </Space>
      )
    }
  ];

  const portColumns = [
    { title: '端口', dataIndex: 'port', key: 'port' },
    { title: '协议', dataIndex: 'protocol', key: 'protocol' },
    { 
      title: '状态', 
      dataIndex: 'state', 
      key: 'state',
      render: (state) => (
        <Tag color={state === 'open' ? 'green' : 'default'}>{state}</Tag>
      )
    },
    { title: '服务', dataIndex: 'service', key: 'service' },
    { title: '产品', dataIndex: 'product', key: 'product' },
    { title: '版本', dataIndex: 'version', key: 'version' }
  ];

  const vulnColumns = [
    { title: '端口', dataIndex: 'port', key: 'port' },
    { title: '脚本', dataIndex: 'script', key: 'script' },
    { 
      title: '输出', 
      dataIndex: 'output', 
      key: 'output',
      ellipsis: true
    }
  ];

  return (
    <div style={{ padding: 24 }}>
      <Title level={2}>
        <ScanOutlined /> Nmap网络扫描
      </Title>
      
      <Card style={{ marginBottom: 24 }}>
        <Space style={{ marginBottom: 16 }}>
          <Button 
            type={activeTab === 'network' ? 'primary' : 'default'}
            icon={<ScanOutlined />}
            onClick={() => setActiveTab('network')}
          >
            网络扫描
          </Button>
          <Button 
            type={activeTab === 'port' ? 'primary' : 'default'}
            icon={<DesktopOutlined />}
            onClick={() => setActiveTab('port')}
          >
            端口扫描
          </Button>
          <Button 
            type={activeTab === 'os' ? 'primary' : 'default'}
            icon={<DesktopOutlined />}
            onClick={() => setActiveTab('os')}
          >
            OS检测
          </Button>
          <Button 
            type={activeTab === 'vuln' ? 'primary' : 'default'}
            icon={<BugOutlined />}
            onClick={() => setActiveTab('vuln')}
          >
            漏洞扫描
          </Button>
        </Space>
        
        {activeTab === 'network' && (
          <Form form={form} layout="inline" onFinish={handleNetworkScan}>
            <Form.Item name="target" label="目标" rules={[{ required: true }]}>
              <Input placeholder="192.168.1.0/24 或 192.168.1.1" style={{ width: 200 }} />
            </Form.Item>
            <Form.Item name="scan_type" label="扫描类型" initialValue="quick">
              <Select style={{ width: 120 }}>
                <Option value="quick">快速扫描</Option>
                <Option value="full">完整扫描</Option>
                <Option value="stealth">隐蔽扫描</Option>
                <Option value="udp">UDP扫描</Option>
              </Select>
            </Form.Item>
            <Form.Item>
              <Button type="primary" htmlType="submit" loading={loading} icon={<ScanOutlined />}>
                开始扫描
              </Button>
            </Form.Item>
          </Form>
        )}
        
        {activeTab === 'port' && (
          <Form layout="inline" onFinish={(v) => handlePortScan(v.target, v.port)}>
            <Form.Item name="target" label="目标" rules={[{ required: true }]}>
              <Input placeholder="192.168.1.1" style={{ width: 150 }} />
            </Form.Item>
            <Form.Item name="port" label="端口" rules={[{ required: true }]}>
              <Input type="number" placeholder="80" style={{ width: 100 }} />
            </Form.Item>
            <Form.Item>
              <Button type="primary" htmlType="submit" loading={loading}>扫描端口</Button>
            </Form.Item>
          </Form>
        )}
        
        {activeTab === 'os' && (
          <Form layout="inline" onFinish={(v) => handleOSScan(v.target)}>
            <Form.Item name="target" label="目标" rules={[{ required: true }]}>
              <Input placeholder="192.168.1.1" style={{ width: 200 }} />
            </Form.Item>
            <Form.Item>
              <Button type="primary" htmlType="submit" loading={loading}>检测OS</Button>
            </Form.Item>
          </Form>
        )}
        
        {activeTab === 'vuln' && (
          <Form layout="inline" onFinish={(v) => handleVulnScan(v.target)}>
            <Form.Item name="target" label="目标" rules={[{ required: true }]}>
              <Input placeholder="192.168.1.1" style={{ width: 200 }} />
            </Form.Item>
            <Form.Item>
              <Button type="primary" htmlType="submit" loading={loading} danger>漏洞扫描</Button>
            </Form.Item>
          </Form>
        )}
      </Card>
      
      {error && <Alert message="错误" description={error} type="error" showIcon style={{ marginBottom: 24 }} />}
      
      <Spin spinning={loading}>
        {scanResult && scanResult.hosts && (
          <Card title="扫描结果">
            <Descriptions bordered column={3} style={{ marginBottom: 16 }}>
              <Descriptions.Item label="目标">{scanResult.target}</Descriptions.Item>
              <Descriptions.Item label="扫描类型">{scanResult.scan_type}</Descriptions.Item>
              <Descriptions.Item label="扫描状态">
                <Tag color="green">{scanResult.status}</Tag>
              </Descriptions.Item>
              <Descriptions.Item label="扫描主机数">{scanResult.summary?.hosts_scanned}</Descriptions.Item>
              <Descriptions.Item label="在线主机">{scanResult.summary?.hosts_up}</Descriptions.Item>
              <Descriptions.Item label="扫描时间">{scanResult.summary?.scan_time}s</Descriptions.Item>
            </Descriptions>
            
            <Divider>主机列表</Divider>
            <Table 
              columns={hostColumns} 
              dataSource={scanResult.hosts} 
              rowKey="address"
              expandable={{
                expandedRowRender: (record) => (
                  <Table 
                    columns={portColumns} 
                    dataSource={record.ports} 
                    rowKey="port"
                    pagination={false}
                    size="small"
                  />
                )
              }}
            />
          </Card>
        )}
        
        {scanResult?.type === 'port' && (
          <Card title="端口扫描结果">
            <Descriptions bordered column={2}>
              <Descriptions.Item label="目标">{scanResult.data.target}</Descriptions.Item>
              <Descriptions.Item label="端口">{scanResult.data.port}</Descriptions.Item>
              <Descriptions.Item label="状态">
                <Tag color={scanResult.data.info?.state === 'open' ? 'green' : 'default'}>
                  {scanResult.data.info?.state}
                </Tag>
              </Descriptions.Item>
              <Descriptions.Item label="服务">{scanResult.data.info?.service}</Descriptions.Item>
              <Descriptions.Item label="产品">{scanResult.data.info?.product}</Descriptions.Item>
              <Descriptions.Item label="版本">{scanResult.data.info?.version}</Descriptions.Item>
            </Descriptions>
          </Card>
        )}
        
        {scanResult?.type === 'os' && (
          <Card title="操作系统检测结果">
            <Descriptions bordered column={2}>
              <Descriptions.Item label="目标">{scanResult.data.target}</Descriptions.Item>
              <Descriptions.Item label="操作系统">
                <Tag color="blue">{scanResult.data.os}</Tag>
              </Descriptions.Item>
            </Descriptions>
          </Card>
        )}
        
        {scanResult?.type === 'vuln' && (
          <Card title="漏洞扫描结果">
            <Descriptions bordered column={2} style={{ marginBottom: 16 }}>
              <Descriptions.Item label="目标">{scanResult.data.target}</Descriptions.Item>
              <Descriptions.Item label="状态">
                <Tag color="green">{scanResult.data.status}</Tag>
              </Descriptions.Item>
            </Descriptions>
            <Table 
              columns={vulnColumns} 
              dataSource={scanResult.data.vulnerabilities} 
              rowKey="script"
            />
          </Card>
        )}
      </Spin>
    </div>
  );
}

export default NmapScan;