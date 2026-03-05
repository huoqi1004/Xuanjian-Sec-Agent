import { useState, useEffect } from 'react';
import { Table, Card, Typography, Button, Input, Select, Space, Tag, Spin, Alert, Modal, Form, Input as AntInput } from 'antd';
import { SearchOutlined, PlusOutlined, EditOutlined, DeleteOutlined, EyeOutlined } from '@ant-design/icons';

const { Title, Text } = Typography;
const { Option } = Select;
const { Search } = Input;

function ThreatIntel() {
  const [localIntel, setLocalIntel] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [selectedRecord, setSelectedRecord] = useState(null);
  const [modalVisible, setModalVisible] = useState(false);
  const [modalType, setModalType] = useState('view'); // view, add, edit
  const [form] = Form.useForm();

  useEffect(() => {
    fetchLocalIntel();
  }, []);

  const fetchLocalIntel = async () => {
    try {
      setLoading(true);
      const response = await fetch('http://localhost:8001/api/v1/dashboard/threat-intel/local');
      if (!response.ok) {
        throw new Error('Failed to fetch local threat intelligence');
      }
      const data = await response.json();
      setLocalIntel(data.records);
      setError(null);
    } catch (err) {
      setError(err.message);
      console.error('Error fetching local threat intelligence:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleViewRecord = (record) => {
    setSelectedRecord(record);
    setModalType('view');
    setModalVisible(true);
  };

  const handleAddRecord = () => {
    form.resetFields();
    setSelectedRecord(null);
    setModalType('add');
    setModalVisible(true);
  };

  const handleEditRecord = (record) => {
    setSelectedRecord(record);
    form.setFieldsValue(record);
    setModalType('edit');
    setModalVisible(true);
  };

  const handleDeleteRecord = (record) => {
    // TODO: 实现删除功能
    console.log('Delete record:', record);
  };

  const handleModalCancel = () => {
    setModalVisible(false);
  };

  const handleModalOk = async () => {
    try {
      const values = await form.validateFields();
      // TODO: 实现添加或编辑功能
      console.log('Form values:', values);
      setModalVisible(false);
      // 重新获取数据
      fetchLocalIntel();
    } catch (error) {
      console.error('Form validation error:', error);
    }
  };

  const columns = [
    {
      title: '指标',
      dataIndex: 'indicator',
      key: 'indicator'
    },
    {
      title: '类型',
      dataIndex: 'indicator_type',
      key: 'indicator_type',
      render: type => <Tag color="blue">{type}</Tag>
    },
    {
      title: '威胁类型',
      dataIndex: 'threat_type',
      key: 'threat_type'
    },
    {
      title: '严重程度',
      dataIndex: 'severity',
      key: 'severity',
      render: severity => {
        let color = 'green';
        if (severity === '中') color = 'orange';
        if (severity === '高') color = 'red';
        return <Tag color={color}>{severity}</Tag>;
      }
    },
    {
      title: '来源',
      dataIndex: 'source',
      key: 'source'
    },
    {
      title: '置信度',
      dataIndex: 'confidence',
      key: 'confidence',
      render: confidence => confidence ? `${confidence}%` : '-'
    },
    {
      title: '首次发现',
      dataIndex: 'first_seen',
      key: 'first_seen'
    },
    {
      title: '最后发现',
      dataIndex: 'last_seen',
      key: 'last_seen'
    },
    {
      title: '操作',
      key: 'action',
      render: (_, record) => (
        <Space size="middle">
          <Button size="small" icon={<EyeOutlined />} onClick={() => handleViewRecord(record)}>查看</Button>
          <Button size="small" icon={<EditOutlined />} onClick={() => handleEditRecord(record)}>编辑</Button>
          <Button size="small" danger icon={<DeleteOutlined />} onClick={() => handleDeleteRecord(record)}>删除</Button>
        </Space>
      )
    }
  ];

  return (
    <div style={{ padding: 24 }}>
      <Title level={2}>威胁情报管理</Title>
      
      {error && (
        <Alert
          message="加载失败"
          description={error}
          type="error"
          showIcon
          action={
            <Button onClick={fetchLocalIntel}>重试</Button>
          }
          style={{ marginBottom: 24 }}
        />
      )}
      
      <Card style={{ marginBottom: 24 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
          <Space>
            <Search
              placeholder="搜索威胁情报"
              allowClear
              style={{ width: 300 }}
            />
            <Select defaultValue="all" style={{ width: 120 }}>
              <Option value="all">全部类型</Option>
              <Option value="ip">IP</Option>
              <Option value="domain">域名</Option>
              <Option value="hash">哈希</Option>
              <Option value="url">URL</Option>
            </Select>
          </Space>
          <Button type="primary" icon={<PlusOutlined />} onClick={handleAddRecord}>添加威胁情报</Button>
        </div>
        
        <Spin spinning={loading}>
          <Table columns={columns} dataSource={localIntel} rowKey="id" />
        </Spin>
      </Card>

      {/* 模态框 */}
      <Modal
        title={
          modalType === 'view' ? '查看威胁情报' :
          modalType === 'add' ? '添加威胁情报' : '编辑威胁情报'
        }
        open={modalVisible}
        onCancel={handleModalCancel}
        onOk={handleModalOk}
      >
        <Form form={form} layout="vertical">
          <Form.Item
            name="indicator"
            label="指标"
            rules={[{ required: true, message: '请输入指标' }]}
          >
            <AntInput placeholder="请输入IP、域名、哈希或URL" />
          </Form.Item>
          
          <Form.Item
            name="indicator_type"
            label="类型"
            rules={[{ required: true, message: '请选择类型' }]}
          >
            <Select placeholder="请选择类型">
              <Option value="ip">IP</Option>
              <Option value="domain">域名</Option>
              <Option value="hash">哈希</Option>
              <Option value="url">URL</Option>
            </Select>
          </Form.Item>
          
          <Form.Item
            name="threat_type"
            label="威胁类型"
          >
            <AntInput placeholder="请输入威胁类型" />
          </Form.Item>
          
          <Form.Item
            name="severity"
            label="严重程度"
            rules={[{ required: true, message: '请选择严重程度' }]}
          >
            <Select placeholder="请选择严重程度">
              <Option value="低">低</Option>
              <Option value="中">中</Option>
              <Option value="高">高</Option>
            </Select>
          </Form.Item>
          
          <Form.Item
            name="description"
            label="描述"
          >
            <AntInput.TextArea rows={4} placeholder="请输入描述" />
          </Form.Item>
          
          <Form.Item
            name="source"
            label="来源"
            rules={[{ required: true, message: '请输入来源' }]}
          >
            <AntInput placeholder="请输入来源" />
          </Form.Item>
          
          <Form.Item
            name="confidence"
            label="置信度"
          >
            <AntInput type="number" placeholder="请输入置信度（0-100）" />
          </Form.Item>
          
          <Form.Item
            name="reference"
            label="参考链接"
          >
            <AntInput placeholder="请输入参考链接" />
          </Form.Item>
        </Form>
      </Modal>
    </div>
  );
}

export default ThreatIntel;