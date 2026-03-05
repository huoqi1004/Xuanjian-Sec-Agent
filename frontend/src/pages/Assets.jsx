import { useState } from 'react';
import { Table, Card, Typography, Button, Input, Select, Space, Tag } from 'antd';
import { PlusOutlined, SearchOutlined, FilterOutlined } from '@ant-design/icons';

const { Title } = Typography;
const { Option } = Select;
const { Search } = Input;

function Assets() {
  const [assets, setAssets] = useState([
    {
      key: '1',
      name: 'Web服务器',
      ip: '192.168.1.100',
      type: '服务器',
      status: '在线',
      riskLevel: '低',
      lastScan: '2026-03-01 10:00:00'
    },
    {
      key: '2',
      name: '数据库服务器',
      ip: '192.168.1.101',
      type: '服务器',
      status: '在线',
      riskLevel: '中',
      lastScan: '2026-03-01 11:30:00'
    },
    {
      key: '3',
      name: '防火墙',
      ip: '192.168.1.1',
      type: '安全设备',
      status: '在线',
      riskLevel: '低',
      lastScan: '2026-03-01 09:00:00'
    },
    {
      key: '4',
      name: '交换机',
      ip: '192.168.1.2',
      type: '网络设备',
      status: '在线',
      riskLevel: '低',
      lastScan: '2026-03-01 08:30:00'
    },
    {
      key: '5',
      name: '邮件服务器',
      ip: '192.168.1.102',
      type: '服务器',
      status: '离线',
      riskLevel: '高',
      lastScan: '2026-02-28 17:00:00'
    }
  ]);

  const columns = [
    {
      title: '资产名称',
      dataIndex: 'name',
      key: 'name'
    },
    {
      title: 'IP地址',
      dataIndex: 'ip',
      key: 'ip'
    },
    {
      title: '资产类型',
      dataIndex: 'type',
      key: 'type',
      filters: [
        { text: '服务器', value: '服务器' },
        { text: '网络设备', value: '网络设备' },
        { text: '安全设备', value: '安全设备' },
        { text: '应用系统', value: '应用系统' }
      ],
      onFilter: (value, record) => record.type === value
    },
    {
      title: '状态',
      dataIndex: 'status',
      key: 'status',
      render: status => (
        <Tag color={status === '在线' ? 'green' : 'red'}>{status}</Tag>
      )
    },
    {
      title: '风险等级',
      dataIndex: 'riskLevel',
      key: 'riskLevel',
      render: riskLevel => {
        let color = 'green';
        if (riskLevel === '中') color = 'orange';
        if (riskLevel === '高') color = 'red';
        return <Tag color={color}>{riskLevel}</Tag>;
      }
    },
    {
      title: '最后扫描时间',
      dataIndex: 'lastScan',
      key: 'lastScan'
    },
    {
      title: '操作',
      key: 'action',
      render: (_, record) => (
        <Space size="middle">
          <Button size="small">详情</Button>
          <Button size="small">扫描</Button>
          <Button size="small">编辑</Button>
        </Space>
      )
    }
  ];

  return (
    <div style={{ padding: 24 }}>
      <Title level={2}>资产管理</Title>
      
      <Card style={{ marginBottom: 24 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
          <Space>
            <Search
              placeholder="搜索资产"
              allowClear
              style={{ width: 300 }}
            />
            <Select defaultValue="all" style={{ width: 120 }}>
              <Option value="all">全部类型</Option>
              <Option value="服务器">服务器</Option>
              <Option value="网络设备">网络设备</Option>
              <Option value="安全设备">安全设备</Option>
              <Option value="应用系统">应用系统</Option>
            </Select>
          </Space>
          <Button type="primary" icon={<PlusOutlined />}>添加资产</Button>
        </div>
        
        <Table columns={columns} dataSource={assets} />
      </Card>
    </div>
  );
}

export default Assets;