import { useState, useEffect, useRef } from 'react';
import { Card, Typography, Button, Input, Space, Tag, List, Avatar, Badge, Tooltip, Select, Spin, Divider, Drawer, Timeline, Empty, message } from 'antd';
import { SendOutlined, RobotOutlined, UserOutlined, ReloadOutlined, SettingOutlined, HistoryOutlined, ThunderboltOutlined, FileTextOutlined, SafetyOutlined, AlertOutlined, ClearOutlined, CopyOutlined, ExpandOutlined, StarOutlined, StarFilled } from '@ant-design/icons';

const { Title, Text, Paragraph } = Typography;
const { TextArea } = Input;
const { Option } = Select;

const API_BASE = 'http://localhost:8001/api/v1/ai';

function AI() {
  const [messages, setMessages] = useState([
    {
      id: 1,
      content: '你好！我是玄鉴安全智能体AI助手。基于先进的AI大模型，我可以帮助你：\n\n🔍 威胁分析 - 分析潜在威胁和攻击模式\n📊 安全评估 - 评估系统安全态势\n🛡️ 防御建议 - 提供安全防护建议\n📝 报告生成 - 自动生成安全报告\n\n请问有什么可以帮到你？',
      type: 'ai',
      timestamp: new Date().toISOString(),
      actions: []
    }
  ]);
  const [inputValue, setInputValue] = useState('');
  const [loading, setLoading] = useState(false);
  const [conversationId, setConversationId] = useState(null);
  const [model, setModel] = useState('supervisor');
  const [modelInfo, setModelInfo] = useState({
    supervisor: { name: 'DeepSeek', desc: '通用安全分析', icon: '🧠' },
    executor: { name: 'Ollama', desc: '本地执行模型', icon: '💻' },
    secgpt: { name: 'SecGPT', desc: '网络安全专用', icon: '🛡️' },
    secgpt_mini: { name: 'SecGPT-Mini', desc: '轻量快速', icon: '⚡' }
  });
  const [showHistory, setShowHistory] = useState(false);
  const [favorites, setFavorites] = useState([]);
  const messagesEndRef = useRef(null);

  const conversationHistory = useRef([]);
  const quickCommands = [
    { label: '🔍 威胁查询', value: '查询IP 8.8.8.8 的威胁情报' },
    { label: '🛡️ 漏洞分析', value: '分析 CVE-2024-1234 漏洞详情' },
    { label: '📊 安全评估', value: '生成当前网络安全态势报告' },
    { label: '⚡ 应急响应', value: '如何处理勒索软件攻击' },
    { label: '📋 工单生成', value: '创建漏洞修复工单' },
    { label: '🧪 渗透测试', value: '模拟一次SQL注入攻击测试' },
    { label: '📝 代码审计', value: '审计以下Java代码的安全性\n\npublic void process(String input) {\n  Runtime.getRuntime().exec(input);\n}' },
    { label: '🔎 日志分析', value: '分析以下安全日志，识别异常\n\n192.168.1.100 - - [04/Mar/2026:10:00:00] "GET /admin.php?id=1\' OR \'1\'=\'1" 500' },
  ];

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  const handleSend = async () => {
    if (!inputValue.trim() || loading) return;

    const userMessage = {
      id: Date.now(),
      content: inputValue,
      type: 'user',
      timestamp: new Date().toISOString()
    };

    setMessages(prev => [...prev, userMessage]);
    conversationHistory.current.push({ role: 'user', content: inputValue });
    setInputValue('');
    setLoading(true);

    try {
      const response = await fetch(`${API_BASE}/chat`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          message: inputValue,
          model: model,
          conversation_id: conversationId,
          history: conversationHistory.current.slice(-10)
        })
      });

      if (!response.ok) throw new Error('API请求失败');

      const data = await response.json();
      const aiMessage = {
        id: Date.now() + 1,
        content: data.response || data.message || 'AI响应内容',
        type: 'ai',
        timestamp: new Date().toISOString(),
        actions: data.actions || [],
        related_events: data.related_events || [],
        confidence: data.confidence
      };

      setMessages(prev => [...prev, aiMessage]);
      conversationHistory.current.push({ role: 'assistant', content: aiMessage.content });
      if (data.conversation_id) setConversationId(data.conversation_id);
    } catch (err) {
      const errorMessage = {
        id: Date.now() + 1,
        content: `⚠️ 请求失败: ${err.message}\n\n请检查后端服务是否运行，或尝试以下解决方案：\n1. 确认 http://localhost:8001 服务正常运行\n2. 检查AI模型配置是否正确\n3. 如需紧急帮助，请联系安全团队`,
        type: 'ai',
        timestamp: new Date().toISOString(),
        isError: true
      };
      setMessages(prev => [...prev, errorMessage]);
    } finally {
      setLoading(false);
    }
  };

  const handleQuickCommand = (command) => {
    setInputValue(command);
    handleSend();
  };

  const handleNewChat = () => {
    setMessages([{
      id: Date.now(),
      content: '对话已重置。有什么可以帮助你？',
      type: 'ai',
      timestamp: new Date().toISOString()
    }]);
    conversationHistory.current = [];
    setConversationId(null);
  };

  const toggleFavorite = (msgId) => {
    setFavorites(prev =>
      prev.includes(msgId) ? prev.filter(id => id !== msgId) : [...prev, msgId]
    );
  };

  const copyToClipboard = (content) => {
    navigator.clipboard.writeText(content);
    message.success('已复制到剪贴板');
  };

  const renderMessageContent = (msg) => {
    const lines = msg.content.split('\n');
    return (
      <div>
        {lines.map((line, idx) => {
          if (line.startsWith('🔍') || line.startsWith('📊') || line.startsWith('🛡️') ||
              line.startsWith('📝') || line.startsWith('⚠️') || line.startsWith('✅') ||
              line.startsWith('❌') || line.startsWith('💡')) {
            return <div key={idx} style={{ fontWeight: 500, marginTop: idx > 0 ? 8 : 0 }}>{line}</div>;
          }
          return <div key={idx}>{line}</div>;
        })}
      </div>
    );
  };

  const SidePanel = () => (
    <div style={{ width: 280, padding: 16 }}>
      <Space direction="vertical" style={{ width: '100%' }} size="middle">
        <Button icon={<ReloadOutlined />} onClick={handleNewChat} block>
          新建对话
        </Button>
        <Button icon={<HistoryOutlined />} onClick={() => setShowHistory(true)} block>
          对话历史
        </Button>
      </Space>

      <Divider />

      <div style={{ marginBottom: 16 }}>
        <Text strong>选择模型</Text>
        <Select
          value={model}
          onChange={setModel}
          style={{ width: '100%', marginTop: 8 }}
        >
          <Option value="supervisor">{modelInfo.supervisor.icon} {modelInfo.supervisor.name}</Option>
          <Option value="executor">{modelInfo.executor.icon} {modelInfo.executor.name}</Option>
          <Option value="secgpt">{modelInfo.secgpt.icon} {modelInfo.secgpt.name}</Option>
          <Option value="secgpt_mini">{modelInfo.secgpt_mini.icon} {modelInfo.secgpt_mini.name}</Option>
        </Select>
      </div>

      <Divider />

      <Text strong>快捷命令</Text>
      <Space direction="vertical" style={{ width: '100%', marginTop: 8 }} size="small">
        {quickCommands.map((cmd, idx) => (
          <Button
            key={idx}
            size="small"
            onClick={() => handleQuickCommand(cmd.value)}
            style={{ textAlign: 'left', justifyContent: 'flex-start' }}
          >
            {cmd.label}
          </Button>
        ))}
      </Space>

      <Divider />

      <Text strong>收藏的回复</Text>
      {favorites.length === 0 ? (
        <Empty description="暂无收藏" image={Empty.PRESENTED_IMAGE_SIMPLE} />
      ) : (
        <List
          size="small"
          dataSource={favorites}
          renderItem={id => {
            const msg = messages.find(m => m.id === id);
            return msg ? (
              <List.Item style={{ cursor: 'pointer' }}>
                <Text ellipsis>{msg.content.substring(0, 30)}...</Text>
              </List.Item>
            ) : null;
          }}
        />
      )}
    </div>
  );

  return (
    <div style={{ display: 'flex', height: 'calc(100vh - 180px)', padding: 24 }}>
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
          <Title level={2} style={{ margin: 0 }}>
            <RobotOutlined style={{ color: '#1890ff', marginRight: 8 }} />
            AI安全助手
          </Title>
          <Space>
            <Badge status={loading ? 'processing' : 'success'} text={loading ? '思考中...' : '在线'} />
            <Tooltip title="设置">
              <Button icon={<SettingOutlined />} />
            </Tooltip>
          </Space>
        </div>

        <Card
          style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}
          bodyStyle={{ flex: 1, display: 'flex', flexDirection: 'column', padding: 0 }}
        >
          <div style={{ flex: 1, overflow: 'auto', padding: 16 }}>
            <List
              dataSource={messages}
              renderItem={item => (
                <List.Item style={{ border: 'none', justifyContent: item.type === 'user' ? 'flex-end' : 'flex-start' }}>
                  <div style={{
                    maxWidth: '75%',
                    display: 'flex',
                    flexDirection: item.type === 'user' ? 'row-reverse' : 'row',
                    alignItems: 'flex-start',
                    gap: 8
                  }}>
                    <Avatar
                      icon={item.type === 'user' ? <UserOutlined /> : <RobotOutlined />}
                      style={{
                        backgroundColor: item.type === 'user' ? '#1890ff' : '#52c41a',
                        flexShrink: 0
                      }}
                    />
                    <div style={{
                      backgroundColor: item.type === 'user' ? '#1890ff' : (item.isError ? '#fff2f0' : '#f0f5ff'),
                      color: item.type === 'user' ? '#fff' : '#333',
                      padding: '12px 16px',
                      borderRadius: 12,
                      border: item.isError ? '1px solid #ffccc7' : 'none',
                      position: 'relative'
                    }}>
                      {renderMessageContent(item)}
                      {item.type === 'ai' && (
                        <Space style={{ marginTop: 8, borderTop: '1px solid #e8e8e8', paddingTop: 8 }}>
                          <Tooltip title="复制">
                            <Button size="small" type="text" icon={<CopyOutlined />} onClick={() => copyToClipboard(item.content)} />
                          </Tooltip>
                          <Tooltip title="收藏">
                            <Button
                              size="small"
                              type="text"
                              icon={favorites.includes(item.id) ? <StarFilled /> : <StarOutlined />}
                              onClick={() => toggleFavorite(item.id)}
                              style={{ color: favorites.includes(item.id) ? '#faad14' : undefined }}
                            />
                          </Tooltip>
                          {item.confidence && (
                            <Tag color="blue">置信度: {item.confidence}%</Tag>
                          )}
                        </Space>
                      )}
                    </div>
                  </div>
                </List.Item>
              )}
            />
            {loading && (
              <div style={{ display: 'flex', justifyContent: 'center', padding: 16 }}>
                <Spin tip="AI正在思考中..." />
              </div>
            )}
            <div ref={messagesEndRef} />
          </div>

          <div style={{ borderTop: '1px solid #e8e8e8', padding: 16 }}>
            <TextArea
              value={inputValue}
              onChange={(e) => setInputValue(e.target.value)}
              placeholder="输入你的安全问题，或使用上方快捷命令..."
              style={{ marginBottom: 12 }}
              autoSize={{ minRows: 2, maxRows: 6 }}
              onPressEnter={(e) => {
                if (e.ctrlKey) {
                  e.preventDefault();
                  handleSend();
                }
              }}
              disabled={loading}
            />
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <Text type="secondary" style={{ fontSize: 12 }}>
                按 Ctrl+Enter 发送 | 支持自然语言查询威胁情报、安全建议等
              </Text>
              <Button
                type="primary"
                icon={<SendOutlined />}
                onClick={handleSend}
                loading={loading}
                disabled={!inputValue.trim()}
              >
                发送
              </Button>
            </div>
          </div>
        </Card>

        {messages.length > 1 && (
          <Card size="small" style={{ marginTop: 16 }}>
            <Space split={<Divider type="vertical" />}>
              <Space>
                <ThunderboltOutlined />
                <Text>上下文记忆: {conversationHistory.current.length} 条</Text>
              </Space>
              <Space>
                <FileTextOutlined />
                <Text>对话ID: {conversationId || '新对话'}</Text>
              </Space>
              <Button size="small" type="link" icon={<ClearOutlined />} onClick={handleNewChat}>
                清除上下文
              </Button>
            </Space>
          </Card>
        )}
      </div>

      <Drawer
        title="对话历史"
        placement="right"
        onClose={() => setShowHistory(false)}
        open={showHistory}
        width={400}
      >
        <Empty description="暂无历史记录" />
      </Drawer>
    </div>
  );
}

export default AI;
