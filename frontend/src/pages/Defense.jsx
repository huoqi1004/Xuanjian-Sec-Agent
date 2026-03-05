import { useState } from 'react';
import { Table, Card, Typography, Button, Input, Select, Space, Tag, Switch } from 'antd';
import { PlusOutlined, SearchOutlined, SafetyOutlined } from '@ant-design/icons';

const { Title } = Typography;
const { Option } = Select;
const { Search } = Input;

function Defense() {
  const [defenseRules, setDefenseRules] = useState([
    {
      key: '1',
      id: 'RULE-001',
      name: 'SQL注入防护',
      type: 'WAF',
      status: '启用',
      priority: '高',
      description: '检测并阻止SQL注入攻击',
      created: '2026-02-20 10:00:00',
      updated: '2026-02-25 14:30:00'
    },
    {
      key: '2',
      id: 'RULE-002',
      name: 'XSS防护',
      type: 'WAF',
      status: '启用',
      priority: '高',
      description: '检测并阻止跨站脚本攻击',
      created: '2026-02-20 10:00:00',
      updated: '2026-02-25 14:30:00'
    },
    {
      key: '3',
      id: 'RULE-003',
      name: 'DDoS防护',
      type: '网络',
      status: '启用',
      priority: '高',
      description: '检测并缓解DDoS攻击',
      created: '2026-02-20 10:00:00',
      updated: '2026-02-25 14:30:00'
    },
    {
      key: '4',
      id: 'RULE-004',
      name: '异常登录检测',
      type: '身份认证',
      status: '启用',
      priority: '中',
      description: '检测并阻止异常登录尝试',
      created: '2026-02-20 10:00:00',
      updated: '2026-02-25 14:30:00'
    },
    {
      key: '5',
      id: 'RULE-005',
      name: '恶意IP拦截',
      type: '网络',
      status: '启用',
      priority: '中',
      description: '拦截已知恶意IP地址',
      created: '2026-02-20 10:00:00',
      updated: '2026-02-25 14:30:00'
    }
  ]);

  const columns = [
    {
      title: '规则ID',
      dataIndex: 'id',
      key: 'id'
    },
    {
      title: '规则名称',
      dataIndex: 'name',
      key: 'name'
    },
    {
      title: '类型',
      dataIndex: 'type',
      key: 'type',
      render: type => (
        <Tag color="blue">{type}</Tag>
      )
    },
    {
      title: '状态',
      dataIndex: 'status',
      key: 'status',
      render: (status, record) => (
        <Switch 
          checked={status === '启用'}
          onChange={(checked) => {
            const newStatus = checked ? '启用' : '禁用';
            setDefenseRules(prev => prev.map(item => 
              item.key === record.key ? { ...item, status: newStatus } : item
            ));
          }}
        />
      )
    },
    {
      title: '优先级',
      dataIndex: 'priority',
      key: 'priority',
      render: priority => {
        let color = 'green';
        if (priority === '中') color = 'orange';
        if (priority === '高') color = 'red';
        return <Tag color={color}>{priority}</Tag>;
      }
    },
    {
      title: '描述',
      dataIndex: 'description',
      key: 'description'
    },
    {
      title: '创建时间',
      dataIndex: 'created',
      key: 'created'
    },
    {
      title: '更新时间',
      dataIndex: 'updated',
      key: 'updated'
    },
    {
      title: '操作',
      key: 'action',
      render: (_, record) => (
        <Space size="middle">
          <Button size="small">详情</Button>
          <Button size="small">编辑</Button>
          <Button size="small">删除</Button>
        </Space>
      )
    }
  ];

  return (
    <div style={{ padding: 24 }}>
      <Title level={2}>防御管理</Title>
      
      <Card style={{ marginBottom: 24 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
          <Space>
            <Search
              placeholder="搜索防御规则"
              allowClear
              style={{ width: 300 }}
            />
            <Select defaultValue="all" style={{ width: 120 }}>
              <Option value="all">全部类型</Option>
              <Option value="WAF">WAF</Option>
              <Option value="网络">网络</Option>
              <Option value="身份认证">身份认证</Option>
            </Select>
          </Space>
          <Button type="primary" icon={<PlusOutlined />}>添加防御规则</Button>
        </div>
        
        <Table columns={columns} dataSource={defenseRules} />
      </Card>
    </div>
  );
}

export default Defense;