import { useState } from 'react';
import { Table, Card, Typography, Button, Input, Select, Space, Tag, Upload, Progress } from 'antd';
import { PlusOutlined, SearchOutlined, FileSearchOutlined } from '@ant-design/icons';
import { InboxOutlined } from '@ant-design/icons';

const { Title } = Typography;
const { Option } = Select;
const { Search } = Input;
const { Dragger } = Upload;

function Forensics() {
  const [forensicsCases, setForensicsCases] = useState([
    {
      key: '1',
      id: 'CASE-001',
      name: 'Web服务器入侵取证',
      status: '进行中',
      type: '网络取证',
      severity: '高',
      investigator: '张三',
      started: '2026-03-01 10:00:00',
      estimated: '2026-03-05 17:00:00'
    },
    {
      key: '2',
      id: 'CASE-002',
      name: '数据泄露事件调查',
      status: '已完成',
      type: '数据取证',
      severity: '高',
      investigator: '李四',
      started: '2026-02-25 09:00:00',
      estimated: '2026-02-29 17:00:00'
    },
    {
      key: '3',
      id: 'CASE-003',
      name: '恶意软件分析',
      status: '已完成',
      type: '恶意软件',
      severity: '中',
      investigator: '王五',
      started: '2026-02-20 14:00:00',
      estimated: '2026-02-22 17:00:00'
    },
    {
      key: '4',
      id: 'CASE-004',
      name: '内部威胁调查',
      status: '待分配',
      type: '内部威胁',
      severity: '中',
      investigator: null,
      started: '2026-03-02 08:00:00',
      estimated: '2026-03-06 17:00:00'
    }
  ]);

  const columns = [
    {
      title: '案件ID',
      dataIndex: 'id',
      key: 'id'
    },
    {
      title: '案件名称',
      dataIndex: 'name',
      key: 'name'
    },
    {
      title: '状态',
      dataIndex: 'status',
      key: 'status',
      render: status => {
        let color = 'green';
        if (status === '进行中') color = 'blue';
        if (status === '待分配') color = 'orange';
        return <Tag color={color}>{status}</Tag>;
      }
    },
    {
      title: '类型',
      dataIndex: 'type',
      key: 'type',
      render: type => (
        <Tag color="purple">{type}</Tag>
      )
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
      title: '调查人员',
      dataIndex: 'investigator',
      key: 'investigator',
      render: investigator => investigator || '未分配'
    },
    {
      title: '开始时间',
      dataIndex: 'started',
      key: 'started'
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
          <Button size="small">分配</Button>
          <Button size="small">关闭</Button>
        </Space>
      )
    }
  ];

  const uploadProps = {
    name: 'file',
    multiple: true,
    action: 'https://run.mocky.io/v3/435e224c-44fb-4773-9faf-380c5e6a2188',
    onChange(info) {
      const { status } = info.file;
      if (status === 'done') {
        console.log(`${info.file.name} file uploaded successfully.`);
      } else if (status === 'error') {
        console.log(`${info.file.name} file upload failed.`);
      }
    },
  };

  return (
    <div style={{ padding: 24 }}>
      <Title level={2}>取证分析</Title>
      
      <Card style={{ marginBottom: 24 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
          <Space>
            <Search
              placeholder="搜索取证案件"
              allowClear
              style={{ width: 300 }}
            />
            <Select defaultValue="all" style={{ width: 120 }}>
              <Option value="all">全部状态</Option>
              <Option value="待分配">待分配</Option>
              <Option value="进行中">进行中</Option>
              <Option value="已完成">已完成</Option>
            </Select>
          </Space>
          <Button type="primary" icon={<PlusOutlined />}>新建取证案件</Button>
        </div>
        
        <Table columns={columns} dataSource={forensicsCases} />
      </Card>
      
      <Card title="上传取证文件" style={{ marginBottom: 24 }}>
        <Dragger {...uploadProps}>
          <p className="ant-upload-drag-icon">
            <InboxOutlined />
          </p>
          <p className="ant-upload-text">点击或拖拽文件到此处上传</p>
          <p className="ant-upload-hint">
            支持上传日志、内存镜像、网络流量等取证文件
          </p>
        </Dragger>
      </Card>
    </div>
  );
}

export default Forensics;