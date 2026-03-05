import { useState, useEffect, useRef } from 'react';
import { Card, Typography, Button, Space, Table, Tag, Row, Col, Statistic, Progress, Timeline, Modal, Input, Alert, List, Badge, Tooltip, message, Divider, Tabs, Rate, Switch, Select } from 'antd';
import { SecurityScanOutlined, RobotOutlined, WarningOutlined, CheckCircleOutlined, ClockCircleOutlined, ThunderboltOutlined, ExperimentOutlined, WarningFilled, SafetyOutlined, ReloadOutlined, PlayCircleOutlined, StopOutlined, FileSearchOutlined, WifiOutlined, AppstoreOutlined } from '@ant-design/icons';
import * as echarts from 'echarts';

const { Title, Text } = Typography;
const { TextArea } = Input;
const { Option } = Select;

const API_BASE = 'http://localhost:8001/api/v1/advanced-defense';

function AdvancedDefense() {
  const [loading, setLoading] = useState(false);
  const [status, setStatus] = useState(null);
  const [threatAnalysis, setThreatAnalysis] = useState(null);
  const [testResults, setTestResults] = useState([]);
  const [scenarios, setScenarios] = useState([]);
  const [agentStatus, setAgentStatus] = useState({});
  const [iocs, setIocs] = useState([]);
  const [activeTab, setActiveTab] = useState('analysis');
  const [analyzeContent, setAnalyzeContent] = useState('');
  const [ransomwareAnalysis, setRansomwareAnalysis] = useState(null);
  const [filePath, setFilePath] = useState('');
  const chartRef = useRef(null);

  useEffect(() => {
    loadData();
  }, []);

  useEffect(() => {
    if (status) {
      initChart();
    }
  }, [status]);

  const loadData = async () => {
    setLoading(true);
    try {
      const [statusRes, testRes, scenariosRes, agentsRes, iocsRes] = await Promise.all([
        fetch(`${API_BASE}/status`).then(r => r.json()).catch(() => null),
        fetch(`${API_BASE}/test/results`).then(r => r.json()).catch(() => ({ results: [] })),
        fetch(`${API_BASE}/simulation/scenarios`).then(r => r.json()).catch(() => ({ scenarios: [] })),
        fetch(`${API_BASE}/agents/status`).then(r => r.json()).catch(() => ({})),
        fetch(`${API_BASE}/ransomware/iocs`).then(r => r.json()).catch(() => ({ iocs: [] }))
      ]);

      setStatus(statusRes);
      setTestResults(testRes?.results || []);
      setScenarios(scenariosRes?.scenarios || []);
      setAgentStatus(agentsRes || {});
      setIocs(iocsRes?.iocs || []);
    } catch (err) {
      console.error('加载数据失败:', err);
    } finally {
      setLoading(false);
    }
  };

  const initChart = () => {
    setTimeout(() => {
      const chart = echarts.init(document.getElementById('defense-chart'));
      const detectionRate = testResults.length > 0 
        ? (testResults.filter(r => r.detection_result?.detected).length / testResults.length * 100).toFixed(1)
        : 0;
      
      chart.setOption({
        tooltip: { trigger: 'item' },
        series: [{
          type: 'pie',
          radius: ['40%', '70%'],
          data: [
            { value: parseFloat(detectionRate), name: '检测率', itemStyle: { color: '#52c41a' } },
            { value: 100 - parseFloat(detectionRate), name: '未检测', itemStyle: { color: '#ff4d4f' } }
          ],
          label: { show: true, formatter: '{b}: {d}%' }
        }]
      });
    }, 100);
  };

  const handleAnalyze = async () => {
    if (!analyzeContent) {
      message.error('请输入要分析的内容');
      return;
    }

    setLoading(true);
    try {
      const res = await fetch(`${API_BASE}/analyze/ai`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(analyzeContent)
      }).then(r => r.json());

      setThreatAnalysis(res);
      message.success('分析完成');
    } catch (err) {
      message.error('分析失败');
    } finally {
      setLoading(false);
    }
  };

  const handleRansomwareAnalyze = async () => {
    if (!filePath) {
      message.error('请输入文件路径');
      return;
    }

    setLoading(true);
    try {
      const res = await fetch(`${API_BASE}/analyze/ransomware`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ file_path: filePath, process_info: null })
      }).then(r => r.json());

      setRansomwareAnalysis(res);
      message.success('勒索软件分析完成');
    } catch (err) {
      message.error('分析失败');
    } finally {
      setLoading(false);
    }
  };

  const handleRunTest = async (scenarioId) => {
    setLoading(true);
    try {
      const res = await fetch(`${API_BASE}/simulation/run/${scenarioId}`, {
        method: 'POST'
      }).then(r => r.json());

      message.success('测试完成');
      loadData();
    } catch (err) {
      message.error('测试失败');
    } finally {
      setLoading(false);
    }
  };

  const testColumns = [
    { title: '场景', dataIndex: ['scenario_name'], key: 'scenario_name' },
    { title: '检测结果', dataIndex: ['detection_result', 'detected'], key: 'detected', render: (v) => v ? <Tag color="green">已检测</Tag> : <Tag color="red">未检测</Tag> },
    { title: '阻断结果', dataIndex: ['response_result', 'blocked'], key: 'blocked', render: (v) => v ? <Tag color="green">已阻断</Tag> : <Tag color="red">未阻断</Tag> },
    { title: '有效性得分', dataIndex: 'effectiveness_score', key: 'score', render: (v) => <Progress percent={v} size="small" strokeColor={v >= 80 ? '#52c41a' : v >= 60 ? '#faad14' : '#ff4d4f'} /> },
    { title: '时间', dataIndex: ['execution_time'], key: 'time', render: (t) => t ? new Date(t).toLocaleString() : '-' }
  ];

  const iocColumns = [
    { title: 'IOC ID', dataIndex: 'id', key: 'id' },
    { title: '名称', dataIndex: 'name', key: 'name' },
    { title: '类别', dataIndex: 'category', key: 'category', render: (c) => <Tag>{c}</Tag> },
    { title: '严重程度', dataIndex: 'severity', key: 'severity', render: (s) => <Tag color={s === 'critical' ? 'red' : 'orange'}>{s}</Tag> },
    { title: '指标', dataIndex: 'indicators', key: 'indicators', render: (arr) => <Text ellipsis>{arr?.join(', ')}</Text> }
  ];

  return (
    <div style={{ padding: 24, background: '#f0f2f5', minHeight: '100vh' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24 }}>
        <Title level={2} style={{ margin: 0 }}>
          <SafetyOutlined style={{ color: '#1890ff', marginRight: 8 }} />
          高级防御系统
        </Title>
        <Space>
          <Button icon={<ReloadOutlined />} onClick={loadData}>刷新</Button>
        </Space>
      </div>

      <Row gutter={[16, 16]} style={{ marginBottom: 24 }}>
        <Col xs={24} sm={12} md={6}>
          <Card hoverable>
            <Statistic
              title="系统状态"
              value={status?.status === 'active' ? '运行中' : '未运行'}
              prefix={status?.status === 'active' ? <CheckCircleOutlined style={{ color: '#52c41a' }} /> : <WarningOutlined style={{ color: '#ff4d4f' }} />}
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} md={6}>
          <Card hoverable>
            <Statistic
              title="AI攻击特征"
              value={status?.threat_intel?.ai_attack_signatures || 0}
              prefix={<RobotOutlined style={{ color: '#1890ff' }} />}
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} md={6}>
          <Card hoverable>
            <Statistic
              title="勒索软件IOC"
              value={status?.threat_intel?.ransomware_iocs || 0}
              prefix={<WarningOutlined style={{ color: '#ff4d4f' }} />}
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} md={6}>
          <Card hoverable>
            <Statistic
              title="防御Agent"
              value={Object.keys(agentStatus).length || 0}
              prefix={<RobotOutlined style={{ color: '#722ed1' }} />}
            />
          </Card>
        </Col>
      </Row>

      <Row gutter={[16, 16]} style={{ marginBottom: 24 }}>
        <Col xs={24} lg={12}>
          <Card title="防御Agent状态">
            <List
              size="small"
              dataSource={Object.entries(agentStatus)}
              renderItem={([id, info]) => (
                <List.Item>
                  <List.Item.Meta
                    avatar={<RobotOutlined style={{ color: '#1890ff' }} />}
                    title={id}
                    description={`类型: ${info.type || 'unknown'}`}
                  />
                  <Tag color={info.status === 'active' ? 'green' : 'default'}>{info.status}</Tag>
                </List.Item>
              )}
            />
          </Card>
        </Col>
        <Col xs={24} lg={12}>
          <Card title="检测效果">
            <div id="defense-chart" style={{ height: 200 }}></div>
          </Card>
        </Col>
      </Row>

      <Card>
        <Tabs activeKey={activeTab} onChange={setActiveTab}>
          <Tabs.TabPane tab={<span><FileSearchOutlined />AI攻击分析</span>} key="analysis">
            <Row gutter={[16, 16]}>
              <Col span={24}>
                <TextArea
                  rows={4}
                  placeholder="输入需要检测的内容（如Prompt注入、越狱攻击等）..."
                  value={analyzeContent}
                  onChange={(e) => setAnalyzeContent(e.target.value)}
                  style={{ marginBottom: 16 }}
                />
                <Button type="primary" icon={<SecurityScanOutlined />} onClick={handleAnalyze} loading={loading}>
                  分析内容
                </Button>
              </Col>
            </Row>

            {threatAnalysis && (
              <Card size="small" style={{ marginTop: 16 }}>
                <Row gutter={[16, 16]}>
                  <Col span={8}>
                    <Statistic
                      title="风险评分"
                      value={threatAnalysis.risk_score}
                      suffix="/100"
                      valueStyle={{ color: threatAnalysis.risk_score >= 70 ? '#ff4d4f' : threatAnalysis.risk_score >= 40 ? '#faad14' : '#52c41a' }}
                    />
                  </Col>
                  <Col span={8}>
                    <Statistic
                      title="检测到威胁"
                      value={threatAnalysis.threats_detected?.length || 0}
                      prefix={<WarningOutlined style={{ color: threatAnalysis.threats_detected?.length > 0 ? '#ff4d4f' : '#52c41a' }} />}
                    />
                  </Col>
                  <Col span={8}>
                    <Statistic
                      title="内容哈希"
                      value={threatAnalysis.content_hash || '-'}
                    />
                  </Col>
                </Row>

                {threatAnalysis.threats_detected?.length > 0 && (
                  <>
                    <Divider>检测到的威胁</Divider>
                    <List
                      size="small"
                      dataSource={threatAnalysis.threats_detected}
                      renderItem={item => (
                        <List.Item>
                          <Alert
                            message={item.attack_name}
                            description={item.description}
                            type={item.severity === 'critical' ? 'error' : item.severity === 'high' ? 'warning' : 'info'}
                            showIcon
                          />
                        </List.Item>
                      )}
                    />
                  </>
                )}

                {threatAnalysis.recommendations?.length > 0 && (
                  <>
                    <Divider>建议</Divider>
                    <List
                      size="small"
                      dataSource={threatAnalysis.recommendations}
                      renderItem={item => <List.Item><Text>{item}</Text></List.Item>}
                    />
                  </>
                )}
              </Card>
            )}
          </Tabs.TabPane>

          <Tabs.TabPane tab={<span><WarningOutlined />勒索软件检测</span>} key="ransomware">
            <Row gutter={[16, 16]}>
              <Col span={24}>
                <Input
                  placeholder="输入文件路径进行勒索软件检测"
                  value={filePath}
                  onChange={(e) => setFilePath(e.target.value)}
                  style={{ marginBottom: 16, width: '50%' }}
                />
                <Button type="primary" icon={<SecurityScanOutlined />} onClick={handleRansomwareAnalyze} loading={loading}>
                  检测
                </Button>
              </Col>
            </Row>

            {ransomwareAnalysis && (
              <Card size="small" style={{ marginTop: 16 }}>
                {ransomwareAnalysis.detection ? (
                  <Alert
                    message="检测到勒索软件行为"
                    description={ransomwareAnalysis.detection.description}
                    type="error"
                    showIcon
                  />
                ) : (
                  <Alert
                    message="未检测到勒索软件行为"
                    description="文件行为正常"
                    type="success"
                    showIcon
                  />
                )}
              </Card>
            )}

            <Divider>勒索软件IOC库</Divider>
            <Table
              columns={iocColumns}
              dataSource={iocs}
              rowKey="id"
              pagination={{ pageSize: 5 }}
              size="small"
            />
          </Tabs.TabPane>

          <Tabs.TabPane tab={<span><ExperimentOutlined />模拟测试</span>} key="test">
            <Row gutter={[16, 16]} style={{ marginBottom: 16 }}>
              <Col span={24}>
                <Text>选择测试场景:</Text>
              </Col>
              {scenarios.map(scenario => (
                <Col key={scenario.id} xs={24} sm={12} md={8}>
                  <Card size="small" hoverable>
                    <Text strong>{scenario.name}</Text>
                    <Text type="secondary" style={{ display: 'block' }}>{scenario.description}</Text>
                    <Button 
                      type="primary" 
                      size="small" 
                      style={{ marginTop: 8 }}
                      icon={<PlayCircleOutlined />}
                      onClick={() => handleRunTest(scenario.id)}
                    >
                      运行测试
                    </Button>
                  </Card>
                </Col>
              ))}
            </Row>

            <Divider>测试结果</Divider>
            <Table
              columns={testColumns}
              dataSource={testResults}
              rowKey="scenario_id"
              pagination={{ pageSize: 5 }}
              size="small"
            />
          </Tabs.TabPane>

          <Tabs.TabPane tab={<span><AppstoreOutlined />攻击序列</span>} key="sequences">
            <Card>
              <Timeline
                items={[
                  {
                    color: 'green',
                    children: (
                      <>
                        <Text strong>1. 初始访问</Text>
                        <br />
                        <Text type="secondary">钓鱼邮件、漏洞利用、恶意下载</Text>
                      </>
                    )
                  },
                  {
                    color: 'green',
                    children: (
                      <>
                        <Text strong>2. 执行</Text>
                        <br />
                        <Text type="secondary">恶意脚本、PowerShell、计划任务</Text>
                      </>
                    )
                  },
                  {
                    color: 'green',
                    children: (
                      <>
                        <Text strong>3. 持久化</Text>
                        <br />
                        <Text type="secondary">注册表、启动项、服务</Text>
                      </>
                    )
                  },
                  {
                    color: 'green',
                    children: (
                      <>
                        <Text strong>4. 权限提升</Text>
                        <br />
                        <Text type="secondary">漏洞利用、凭证窃取</Text>
                      </>
                    )
                  },
                  {
                    color: 'orange',
                    children: (
                      <>
                        <Text strong>5. 内网侦察</Text>
                        <br />
                        <Text type="secondary">端口扫描、用户枚举</Text>
                      </>
                    )
                  },
                  {
                    color: 'red',
                    children: (
                      <>
                        <Text strong>6. 横向移动</Text>
                        <br />
                        <Text type="secondary">PsExec、WMI、RDP</Text>
                      </>
                    )
                  },
                  {
                    color: 'red',
                    children: (
                      <>
                        <Text strong>7. 数据外泄</Text>
                        <br />
                        <Text type="secondary">压缩上传、云存储</Text>
                      </>
                    )
                  },
                  {
                    color: 'red',
                    children: (
                      <>
                        <Text strong>8. 加密</Text>
                        <br />
                        <Text type="secondary">文件加密、勒索信息</Text>
                      </>
                    )
                  }
                ]}
              />
            </Card>
          </Tabs.TabPane>
        </Tabs>
      </Card>
    </div>
  );
}

export default AdvancedDefense;
