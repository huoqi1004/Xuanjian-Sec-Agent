import { useState, useEffect, useRef } from 'react';
import { Row, Col, Card, Typography, Statistic, Progress, Badge, Spin, Alert, Space, Tag, Table, Timeline, Button, Tooltip, List, Avatar } from 'antd';
import { ReloadOutlined, SecurityScanOutlined, BugOutlined, WarningOutlined, SafetyOutlined, CloudServerOutlined, GlobalOutlined, LockOutlined, ClockCircleOutlined, CheckCircleOutlined, ExclamationCircleOutlined, ArrowRightOutlined, ThunderboltOutlined, SettingOutlined } from '@ant-design/icons';
import * as echarts from 'echarts';

const { Title, Text } = Typography;

const API_BASE = 'http://localhost:8001/api/v1/dashboard';

function Dashboard() {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [securityData, setSecurityData] = useState(null);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const chartRefs = useRef({});

  useEffect(() => {
    fetchSecurityData();
    const interval = autoRefresh ? setInterval(fetchSecurityData, 30000) : null;
    return () => {
      if (interval) clearInterval(interval);
      Object.values(chartRefs.current).forEach(chart => chart?.dispose());
    };
  }, [autoRefresh]);

  useEffect(() => {
    if (securityData && !loading) {
      initCharts();
    }
  }, [securityData, loading]);

  const fetchSecurityData = async () => {
    try {
      setLoading(true);
      const response = await fetch(`${API_BASE}/security-posture`);
      if (!response.ok) throw new Error('获取数据失败');
      const data = await response.json();
      setSecurityData({
        assets: { total: 1234, distribution: [
          { value: 456, name: '服务器' },
          { value: 320, name: '网络设备' },
          { value: 280, name: '终端' },
          { value: 98, name: 'Web应用' },
          { value: 80, name: '数据库' }
        ]},
        threats: { 
          total: 89, 
          trend: [12, 15, 8, 18, 22, 14],
          critical: 12,
          high: 28,
          medium: 35,
          low: 14
        },
        vulnerabilities: { 
          total: 156,
          critical: 8,
          high: 32,
          medium: 68,
          low: 48
        },
        security_score: 78,
        recent_events: [
          { time: '10:30:25', type: 'threat', content: '检测到SQL注入攻击', level: 'high' },
          { time: '10:28:15', type: 'vuln', content: '新发现高危漏洞CVE-2026-1234', level: 'critical' },
          { time: '10:25:00', type: 'asset', content: '新增服务器 192.168.1.100', level: 'info' },
          { time: '10:20:30', type: 'waf', content: 'WAF拦截攻击 125.2.1.1', level: 'medium' }
        ],
        top_attacks: [
          { name: 'SQL注入', count: 456, trend: '+12%' },
          { name: 'XSS攻击', count: 328, trend: '+5%' },
          { name: '命令注入', count: 156, trend: '-3%' },
          { name: '暴力破解', count: 89, trend: '+8%' }
        ]
      });
      setError(null);
    } catch (err) {
      setError(err.message);
      setSecurityData({
        assets: { total: 1234, distribution: [
          { value: 456, name: '服务器' },
          { value: 320, name: '网络设备' },
          { value: 280, name: '终端' },
          { value: 98, name: 'Web应用' },
          { value: 80, name: '数据库' }
        ]},
        threats: { 
          total: 89, 
          trend: [12, 15, 8, 18, 22, 14],
          critical: 12,
          high: 28,
          medium: 35,
          low: 14
        },
        vulnerabilities: { 
          total: 156,
          critical: 8,
          high: 32,
          medium: 68,
          low: 48
        },
        security_score: 78,
        recent_events: [
          { time: '10:30:25', type: 'threat', content: '检测到SQL注入攻击', level: 'high' },
          { time: '10:28:15', type: 'vuln', content: '新发现高危漏洞CVE-2026-1234', level: 'critical' },
          { time: '10:25:00', type: 'asset', content: '新增服务器 192.168.1.100', level: 'info' },
          { time: '10:20:30', type: 'waf', content: 'WAF拦截攻击 125.2.1.1', level: 'medium' }
        ],
        top_attacks: [
          { name: 'SQL注入', count: 456, trend: '+12%' },
          { name: 'XSS攻击', count: 328, trend: '+5%' },
          { name: '命令注入', count: 156, trend: '-3%' },
          { name: '暴力破解', count: 89, trend: '+8%' }
        ]
      });
    } finally {
      setLoading(false);
    }
  };

  const initCharts = () => {
    const threatChart = echarts.init(document.getElementById('threat-chart'));
    threatChart.setOption({
      tooltip: { trigger: 'axis' },
      legend: { data: ['高危', '中危', '低危'], bottom: 0, textStyle: { color: '#666' } },
      grid: { left: '3%', right: '4%', bottom: '15%', top: '10%', containLabel: true },
      xAxis: { type: 'category', boundaryGap: false, data: ['00:00', '04:00', '08:00', '12:00', '16:00', '20:00'] },
      yAxis: { type: 'value' },
      series: [
        { name: '高危', type: 'line', smooth: true, data: [12, 15, 8, 18, 22, 14], itemStyle: { color: '#ff4d4f' }, areaStyle: { color: 'rgba(255,77,79,0.1)' } },
        { name: '中危', type: 'line', smooth: true, data: [25, 28, 22, 35, 42, 30], itemStyle: { color: '#fa8c16' }, areaStyle: { color: 'rgba(250,140,22,0.1)' } },
        { name: '低危', type: 'line', smooth: true, data: [45, 52, 48, 62, 78, 56], itemStyle: { color: '#1890ff' }, areaStyle: { color: 'rgba(24,144,255,0.1)' } }
      ]
    });
    chartRefs.current.threat = threatChart;

    const assetChart = echarts.init(document.getElementById('asset-chart'));
    assetChart.setOption({
      tooltip: { trigger: 'item', formatter: '{b}: {c} ({d}%)' },
      legend: { orient: 'vertical', right: 10, top: 'center', textStyle: { color: '#666' } },
      series: [{
        type: 'pie',
        radius: ['40%', '70%'],
        avoidLabelOverlap: false,
        itemStyle: { borderRadius: 8, borderColor: '#fff', borderWidth: 2 },
        label: { show: false },
        emphasis: { label: { show: true, fontSize: 14, fontWeight: 'bold' } },
        data: securityData.assets.distribution,
        color: ['#1890ff', '#52c41a', '#fa8c16', '#ff4d4f', '#722ed1']
      }]
    });
    chartRefs.current.asset = assetChart;

    const vulnChart = echarts.init(document.getElementById('vuln-chart'));
    vulnChart.setOption({
      tooltip: {},
      radar: {
        indicator: [
          { name: '系统漏洞', max: 100 },
          { name: 'Web漏洞', max: 100 },
          { name: '数据库漏洞', max: 100 },
          { name: '网络漏洞', max: 100 },
          { name: '应用漏洞', max: 100 }
        ],
        splitArea: { areaStyle: { color: ['rgba(24,144,255,0.02)', 'rgba(24,144,255,0.04)'] } }
      },
      series: [{
        type: 'radar',
        data: [{ value: [80, 65, 45, 70, 55], name: '漏洞分布', itemStyle: { color: '#ff4d4f' }, areaStyle: { color: 'rgba(255,77,79,0.2)' } }]
      }]
    });
    chartRefs.current.vuln = vulnChart;

    const attackChart = echarts.init(document.getElementById('attack-chart'));
    attackChart.setOption({
      tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' } },
      grid: { left: '3%', right: '4%', bottom: '3%', top: '10%', containLabel: true },
      xAxis: { type: 'category', data: securityData.top_attacks.map(a => a.name) },
      yAxis: { type: 'value' },
      series: [{
        type: 'bar',
        data: securityData.top_attacks.map((a, i) => ({
          value: a.count,
          itemStyle: { color: ['#ff4d4f', '#fa8c16', '#1890ff', '#52c41a'][i] }
        })),
        barWidth: '50%',
        label: { show: true, position: 'top' }
      }]
    });
    chartRefs.current.attack = attackChart;

    window.addEventListener('resize', () => {
      Object.values(chartRefs.current).forEach(chart => chart?.resize());
    });
  };

  const getScoreColor = (score) => {
    if (score >= 90) return '#52c41a';
    if (score >= 70) return '#1890ff';
    if (score >= 60) return '#fa8c16';
    return '#ff4d4f';
  };

  const getEventIcon = (type) => {
    switch (type) {
      case 'threat': return <WarningOutlined style={{ color: '#ff4d4f' }} />;
      case 'vuln': return <BugOutlined style={{ color: '#fa8c16' }} />;
      case 'asset': return <CloudServerOutlined style={{ color: '#1890ff' }} />;
      case 'waf': return <SafetyOutlined style={{ color: '#722ed1' }} />;
      default: return <SecurityScanOutlined />;
    }
  };

  if (loading && !securityData) {
    return (
      <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '80vh' }}>
        <Spin size="large" tip="加载安全态势数据..." />
      </div>
    );
  }

  return (
    <div style={{ padding: 24, background: '#f0f2f5', minHeight: '100vh' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24 }}>
        <Title level={2} style={{ margin: 0 }}>
          <SafetyOutlined style={{ color: '#1890ff', marginRight: 8 }} />
          安全态势大屏
        </Title>
        <Space>
          <Button
            type={autoRefresh ? 'primary' : 'default'}
            icon={<ReloadOutlined spin={autoRefresh} />}
            onClick={() => setAutoRefresh(!autoRefresh)}
          >
            {autoRefresh ? '自动刷新中' : '关闭自动刷新'}
          </Button>
          <Button icon={<ReloadOutlined />} onClick={fetchSecurityData}>刷新数据</Button>
        </Space>
      </div>

      {error && (
        <Alert
          message="数据加载异常"
          description={error}
          type="warning"
          showIcon
          style={{ marginBottom: 16 }}
          closable
        />
      )}

      <Row gutter={[16, 16]} style={{ marginBottom: 24 }}>
        <Col xs={24} sm={12} md={6}>
          <Card hoverable style={{ background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)', border: 'none' }}>
            <Statistic
              title={<span style={{ color: 'rgba(255,255,255,0.85)' }}>安全评分</span>}
              value={securityData?.security_score || 0}
              suffix="/100"
              prefix={<SafetyOutlined style={{ color: '#fff' }} />}
              valueStyle={{ color: '#fff', fontWeight: 'bold', fontSize: 32 }}
            />
            <Progress
              percent={securityData?.security_score || 0}
              strokeColor="#fff"
              trailColor="rgba(255,255,255,0.3)"
              showInfo={false}
              style={{ marginTop: 8 }}
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} md={6}>
          <Card hoverable>
            <Statistic
              title="资产总数"
              value={securityData?.assets.total || 0}
              prefix={<CloudServerOutlined style={{ color: '#1890ff' }} />}
              valueStyle={{ fontSize: 28 }}
            />
            <Space style={{ marginTop: 8 }}>
              <Tag color="blue">服务器 {securityData?.assets.distribution?.[0]?.value || 456}</Tag>
              <Tag color="green">终端 {securityData?.assets.distribution?.[2]?.value || 280}</Tag>
            </Space>
          </Card>
        </Col>
        <Col xs={24} sm={12} md={6}>
          <Card hoverable>
            <Statistic
              title="威胁数量"
              value={securityData?.threats.total || 0}
              prefix={<WarningOutlined style={{ color: '#ff4d4f' }} />}
              valueStyle={{ color: '#cf1322', fontSize: 28 }}
            />
            <Space style={{ marginTop: 8 }}>
              <Tag color="red">严重 {securityData?.threats.critical || 12}</Tag>
              <Tag color="orange">高危 {securityData?.threats.high || 28}</Tag>
            </Space>
          </Card>
        </Col>
        <Col xs={24} sm={12} md={6}>
          <Card hoverable>
            <Statistic
              title="漏洞数量"
              value={securityData?.vulnerabilities.total || 0}
              prefix={<BugOutlined style={{ color: '#fa8c16' }} />}
              valueStyle={{ color: '#d48806', fontSize: 28 }}
            />
            <Space style={{ marginTop: 8 }}>
              <Tag color="red">严重 {securityData?.vulnerabilities.critical || 8}</Tag>
              <Tag color="orange">高危 {securityData?.vulnerabilities.high || 32}</Tag>
            </Space>
          </Card>
        </Col>
      </Row>

      <Row gutter={[16, 16]} style={{ marginBottom: 24 }}>
        <Col xs={24} lg={12}>
          <Card 
            title={
              <Space>
                <WarningOutlined style={{ color: '#ff4d4f' }} />
                <span>威胁趋势</span>
                <Tag color="red">今日 {securityData?.threats.total || 0}</Tag>
              </Space>
            }
          >
            <div id="threat-chart" style={{ height: 280 }}></div>
          </Card>
        </Col>
        <Col xs={24} lg={12}>
          <Card 
            title={
              <Space>
                <CloudServerOutlined style={{ color: '#1890ff' }} />
                <span>资产分布</span>
              </Space>
            }
          >
            <div id="asset-chart" style={{ height: 280 }}></div>
          </Card>
        </Col>
      </Row>

      <Row gutter={[16, 16]} style={{ marginBottom: 24 }}>
        <Col xs={24} lg={12}>
          <Card 
            title={
              <Space>
                <BugOutlined style={{ color: '#fa8c16' }} />
                <span>漏洞分布</span>
              </Space>
            }
          >
            <div id="vuln-chart" style={{ height: 280 }}></div>
          </Card>
        </Col>
        <Col xs={24} lg={12}>
          <Card 
            title={
              <Space>
                <ThunderboltOutlined style={{ color: '#ff4d4f' }} />
                <span>攻击类型TOP4</span>
              </Space>
            }
          >
            <div id="attack-chart" style={{ height: 280 }}></div>
          </Card>
        </Col>
      </Row>

      <Row gutter={[16, 16]}>
        <Col xs={24} lg={16}>
          <Card 
            title={
              <Space>
                <ClockCircleOutlined style={{ color: '#1890ff' }} />
                <span>最新安全事件</span>
              </Space>
            }
          >
            <List
              dataSource={securityData?.recent_events || []}
              renderItem={item => (
                <List.Item>
                  <List.Item.Meta
                    avatar={getEventIcon(item.type)}
                    title={<Text>{item.content}</Text>}
                    description={item.time}
                  />
                  <Tag color={item.level === 'critical' ? 'red' : item.level === 'high' ? 'orange' : item.level === 'medium' ? 'gold' : 'blue'}>
                    {item.level === 'critical' ? '严重' : item.level === 'high' ? '高危' : item.level === 'medium' ? '中危' : '信息'}
                  </Tag>
                </List.Item>
              )}
            />
          </Card>
        </Col>
        <Col xs={24} lg={8}>
          <Card 
            title={
              <Space>
                <SecurityScanOutlined style={{ color: '#52c41a' }} />
                <span>安全评分详情</span>
              </Space>
            }
          >
            <Space direction="vertical" style={{ width: '100%' }} size="middle">
              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                  <Text>检测能力</Text>
                  <Text strong>85%</Text>
                </div>
                <Progress percent={85} strokeColor="#52c41a" />
              </div>
              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                  <Text>防御能力</Text>
                  <Text strong>72%</Text>
                </div>
                <Progress percent={72} strokeColor="#1890ff" />
              </div>
              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                  <Text>响应能力</Text>
                  <Text strong>68%</Text>
                </div>
                <Progress percent={68} strokeColor="#fa8c16" />
              </div>
              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                  <Text>恢复能力</Text>
                  <Text strong>80%</Text>
                </div>
                <Progress percent={80} strokeColor="#722ed1" />
              </div>
              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                  <Text>合规水平</Text>
                  <Text strong>85%</Text>
                </div>
                <Progress percent={85} strokeColor="#13c2c2" />
              </div>
            </Space>
          </Card>
        </Col>
      </Row>
    </div>
  );
}

export default Dashboard;
