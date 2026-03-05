import { useState } from 'react';
import { Card, Typography, Form, Input, Select, Button, Table, Tag, Space, Spin, Alert, Descriptions, Divider, Tabs, Row, Col } from 'antd';
import { SearchOutlined, GlobalOutlined, FileTextOutlined, LinkOutlined } from '@ant-design/icons';

const { Title, Text } = Typography;
const { Option } = Select;
const { TabPane } = Tabs;

const API_BASE = 'http://localhost:8001/api/v1/security';

function ThreatIntelQuery() {
  const [form] = Form.useForm();
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [activeTab, setActiveTab] = useState('single');

  const handleQuery = async (values) => {
    setLoading(true);
    setError(null);
    setResult(null);
    
    try {
      const response = await fetch(`${API_BASE}/threat-intel/query`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(values)
      });
      
      if (!response.ok) throw new Error('查询失败');
      
      const data = await response.json();
      setResult(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const getIndicatorIcon = (type) => {
    switch (type) {
      case 'ip': return <GlobalOutlined />;
      case 'domain': return <GlobalOutlined />;
      case 'hash': return <FileTextOutlined />;
      case 'url': return <LinkOutlined />;
      default: return <SearchOutlined />;
    }
  };

  const renderMicrostepResult = (data) => {
    if (!data) return null;
    
    return (
      <Card title="微步在线" size="small" style={{ marginBottom: 16 }}>
        {data.response_code === 0 ? (
          <>
            <Descriptions bordered column={2} size="small">
              <Descriptions.Item label="严重程度">
                <Tag color={
                  data.data?.severity === 'high' ? 'red' : 
                  data.data?.severity === 'medium' ? 'orange' : 'green'
                }>
                  {data.data?.severity || '未知'}
                </Tag>
              </Descriptions.Item>
              <Descriptions.Item label="置信度">{data.data?.confidence || '-'}%</Descriptions.Item>
              <Descriptions.Item label="判断">{data.data?.judgments?.join(', ') || '-'}</Descriptions.Item>
              <Descriptions.Item label="标签">{data.data?.tags?.join(', ') || '-'}</Descriptions.Item>
            </Descriptions>
            {data.data?.threat_types && (
              <>
                <Divider>威胁类型</Divider>
                <Space wrap>
                  {data.data.threat_types.map((type, idx) => (
                    <Tag key={idx} color="red">{type}</Tag>
                  ))}
                </Space>
              </>
            )}
          </>
        ) : (
          <Alert type="warning" message="查询失败" description={data.verbose_msg} />
        )}
      </Card>
    );
  };

  const renderVirusTotalResult = (data) => {
    if (!data) return null;
    
    const stats = data.data?.attributes?.last_analysis_stats;
    
    return (
      <Card title="VirusTotal" size="small">
        {stats && (
          <Descriptions bordered column={4} size="small">
            <Descriptions.Item label="恶意">
              <Tag color="red">{stats.malicious}</Tag>
            </Descriptions.Item>
            <Descriptions.Item label="可疑">
              <Tag color="orange">{stats.suspicious}</Tag>
            </Descriptions.Item>
            <Descriptions.Item label="安全">
              <Tag color="green">{stats.harmless}</Tag>
            </Descriptions.Item>
            <Descriptions.Item label="未检测">
              <Tag>{stats.undetected}</Tag>
            </Descriptions.Item>
          </Descriptions>
        )}
        <Divider>检测详情</Divider>
        <Table 
          size="small" 
          dataSource={Object.entries(data.data?.attributes?.last_analysis_results || {}).slice(0, 5).map(([engine, info]) => ({
            engine,
          }))}
          columns={[
            { title: '引擎', dataIndex: 'engine', key: 'engine' },
            { title: '结果', dataIndex: ['info', 'result'], key: 'result' }
          ]}
          pagination={false}
        />
      </Card>
    );
  };

  return (
    <div style={{ padding: 24 }}>
      <Title level={2}>
        <SearchOutlined /> 威胁情报查询
      </Title>
      
      <Card style={{ marginBottom: 24 }}>
        <Tabs activeKey={activeTab} onChange={setActiveTab}>
          <TabPane tab="single" key="single">
            <Form form={form} layout="inline" onFinish={handleQuery} style={{ marginTop: 16 }}>
              <Form.Item name="indicator" label="指标" rules={[{ required: true }]}>
                <Input placeholder="IP / 域名 / 哈希 / URL" style={{ width: 300 }} />
              </Form.Item>
              <Form.Item name="indicator_type" label="类型" initialValue="ip" rules={[{ required: true }]}>
                <Select style={{ width: 120 }}>
                  <Option value="ip">IP地址</Option>
                  <Option value="domain">域名</Option>
                  <Option value="hash">文件哈希</Option>
                  <Option value="url">URL</Option>
                </Select>
              </Form.Item>
              <Form.Item>
                <Button type="primary" htmlType="submit" loading={loading} icon={<SearchOutlined />}>
                  查询
                </Button>
              </Form.Item>
            </Form>
          </TabPane>
        </Tabs>
      </Card>
      
      {error && <Alert message="错误" description={error} type="error" showIcon style={{ marginBottom: 24 }} />}
      
      <Spin spinning={loading}>
        {result && (
          <>
            <Card style={{ marginBottom: 16 }}>
              <Descriptions bordered column={4}>
                <Descriptions.Item label="查询指标">
                  <Text strong>{result.indicator}</Text>
                </Descriptions.Item>
                <Descriptions.Item label="指标类型">
                  <Tag color="blue">{result.type}</Tag>
                </Descriptions.Item>
              </Descriptions>
            </Card>
            
            <Row gutter={16}>
              <Col span={12}>
                {renderMicrostepResult(result.results?.microstep)}
              </Col>
              <Col span={12}>
                {renderVirusTotalResult(result.results?.virustotal)}
              </Col>
            </Row>
          </>
        )}
      </Spin>
    </div>
  );
}

export default ThreatIntelQuery;