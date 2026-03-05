import { useState } from 'react';
import { Table, Card, Typography, Button, Input, Select, Space, Tag, Progress, Steps } from 'antd';
import { PlusOutlined, SearchOutlined, RocketOutlined } from '@ant-design/icons';

const { Title } = Typography;
const { Option } = Select;
const { Search } = Input;
const { Step } = Steps;

function Workflow() {
  const [workflows, setWorkflows] = useState([
    {
      key: '1',
      id: 'WF-001',
      name: '安全扫描工作流',
      status: '运行中',
      type: '扫描',
      progress: 75,
      started: '2026-03-01 10:00:00',
      estimated: '2026-03-01 11:30:00',
      steps: [
        { title: '资产发现', status: 'finish' },
        { title: '漏洞扫描', status: 'finish' },
        { title: '威胁分析', status: 'process' },
        { title: '报告生成', status: 'wait' }
      ]
    },
    {
      key: '2',
      id: 'WF-002',
      name: '事件响应工作流',
      status: '已完成',
      type: '响应',
      progress: 100,
      started: '2026-02-29 14:00:00',
      estimated: '2026-02-29 16:00:00',
      steps: [
        { title: '事件检测', status: 'finish' },
        { title: '初步分析', status: 'finish' },
        { title: '响应措施', status: 'finish' },
        { title: '恢复验证', status: 'finish' }
      ]
    },
    {
      key: '3',
      id: 'WF-003',
      name: '合规检查工作流',
      status: '待执行',
      type: '合规',
      progress: 0,
      started: null,
      estimated: '2026-03-03 10:00:00',
      steps: [
        { title: '策略检查', status: 'wait' },
        { title: '配置审计', status: 'wait' },
        { title: '漏洞评估', status: 'wait' },
        { title: '合规报告', status: 'wait' }
      ]
    }
  ]);

  const columns = [
    {
      title: '工作流ID',
      dataIndex: 'id',
      key: 'id'
    },
    {
      title: '工作流名称',
      dataIndex: 'name',
      key: 'name'
    },
    {
      title: '状态',
      dataIndex: 'status',
      key: 'status',
      render: status => {
        let color = 'green';
        if (status === '运行中') color = 'blue';
        if (status === '待执行') color = 'orange';
        return <Tag color={color}>{status}</Tag>;
      }
    },
    {
      title: '类型',
      dataIndex: 'type',
      key: 'type',
      render: type => (
        <Tag color="cyan">{type}</Tag>
      )
    },
    {
      title: '进度',
      dataIndex: 'progress',
      key: 'progress',
      render: progress => (
        <Progress percent={progress} size="small" status={progress === 100 ? "success" : "active"} />
      )
    },
    {
      title: '开始时间',
      dataIndex: 'started',
      key: 'started',
      render: started => started || '未开始'
    },
    {
      title: '预计完成时间',
      dataIndex: 'estimated',
      key: 'estimated'
    },
    {
      title: '操作',
      key: 'action',
      render: (_, record) => (
        <Space size="middle">
          <Button size="small">详情</Button>
          <Button size="small">暂停</Button>
          <Button size="small">取消</Button>
        </Space>
      )
    }
  ];

  return (
    <div style={{ padding: 24 }}>
      <Title level={2}>工作流管理</Title>
      
      <Card style={{ marginBottom: 24 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
          <Space>
            <Search
              placeholder="搜索工作流"
              allowClear
              style={{ width: 300 }}
            />
            <Select defaultValue="all" style={{ width: 120 }}>
              <Option value="all">全部类型</Option>
              <Option value="扫描">扫描</Option>
              <Option value="响应">响应</Option>
              <Option value="合规">合规</Option>
            </Select>
          </Space>
          <Button type="primary" icon={<PlusOutlined />}>创建工作流</Button>
        </div>
        
        <Table columns={columns} dataSource={workflows} />
      </Card>
      
      {/* 工作流详情示例 */}
      <Card title="工作流详情" style={{ marginBottom: 24 }}>
        <div style={{ marginBottom: 24 }}>
          <h3>安全扫描工作流 (WF-001)</h3>
          <p>状态: <Tag color="blue">运行中</Tag></p>
          <p>进度: <Progress percent={75} status="active" /></p>
        </div>
        
        <Steps current={2}>
          <Step title="资产发现" description="已完成" />
          <Step title="漏洞扫描" description="已完成" />
          <Step title="威胁分析" description="进行中" />
          <Step title="报告生成" description="待执行" />
        </Steps>
        
        <div style={{ marginTop: 24, display: 'flex', justifyContent: 'flex-end' }}>
          <Space>
            <Button>暂停</Button>
            <Button>取消</Button>
            <Button type="primary">继续</Button>
          </Space>
        </div>
      </Card>
    </div>
  );
}

export default Workflow;