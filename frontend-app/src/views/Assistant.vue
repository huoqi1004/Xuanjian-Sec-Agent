<template>
  <div class="assistant-page">
    <div class="page-header">
      <div>
        <div class="page-title">AI安全助手</div>
        <div class="page-desc">智能对话 · 报告生成 · 威胁分析 · 告警查询</div>
      </div>
      <el-button type="danger" plain size="small" @click="clearHistory">
        <el-icon><Delete /></el-icon> 清除对话
      </el-button>
    </div>

    <div class="assistant-container">
      <div ref="chatContainer" class="chat-messages">
        <div
          v-for="(msg, idx) in messages"
          :key="idx"
          :class="['message', msg.role === 'user' ? 'user-message' : 'assistant-message']"
        >
          <div class="message-avatar">
            <el-icon v-if="msg.role === 'user'" size="24"><User /></el-icon>
            <el-icon v-else size="24"><ChatDotRound /></el-icon>
          </div>
          <div class="message-content">
            <!-- eslint-disable-next-line vue/no-v-html -- 内容已由 formatContent 转义后渲染轻量 Markdown -->
            <div class="message-bubble" v-html="formatContent(msg.content)"></div>
          </div>
        </div>
        <div v-if="loading" class="message assistant-message">
          <div class="message-avatar">
            <el-icon size="24"><ChatDotRound /></el-icon>
          </div>
          <div class="message-content">
            <div class="message-bubble loading">
              <span class="loading-dot"></span>
              <span class="loading-dot"></span>
              <span class="loading-dot"></span>
            </div>
          </div>
        </div>
      </div>

      <div class="chat-input">
        <el-input
          v-model="inputMessage"
          type="textarea"
          :rows="2"
          placeholder="输入消息，Enter发送，Shift+Enter换行..."
          :disabled="loading"
          @keydown="handleKeyDown"
        />
        <el-button type="primary" :loading="loading" :disabled="!inputMessage.trim()" @click="sendMessage">
          <el-icon><Promotion /></el-icon> 发送
        </el-button>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue';
import { Delete, User, ChatDotRound, Promotion } from '@element-plus/icons-vue';
import { legacyApi } from '@/api';

interface ChatMessage {
  role: string;
  content: string;
  is_report?: boolean;
}

const conversationId = ref('default');
const messages = ref<ChatMessage[]>([]);
const inputMessage = ref('');
const loading = ref(false);
const chatContainer = ref<HTMLElement>();

// 初始化欢迎消息
onMounted(() => {
  messages.value = [
    {
      role: 'assistant',
      content: `👋 您好！我是玄鉴安全智能体，基于DeepSeek V4 Pro驱动的AI安全助手。\n\n我可以帮助您：\n\n📊 **报告生成**\n- 生成每日/每周/每月安全报告\n- 生成扫描报告和基线检查报告\n\n **威胁情报查询**\n- 查询IP、域名、哈希等威胁指标\n- 分析恶意软件哈希\n\n⚠️ **告警分析**\n- 查看和筛选安全告警\n- 深度分析告警数据\n\n🔧 **系统操作**\n- 检查系统健康状态\n- 管理对话历史\n\n💬 您可以直接输入问题或使用命令与我交流。输入"help"查看所有可用命令。`
    }
  ];
  loadHistory();
});

async function loadHistory() {
  try {
    const res = await legacyApi.get<{ messages: ChatMessage[] }>('/ai/history/' + conversationId.value);
    if (res.code === 0 && res.data.messages.length > 0) {
      messages.value = res.data.messages;
    }
  } catch (err) {
    console.error('加载历史记录失败:', err);
  }
}

async function sendMessage() {
  if (!inputMessage.value.trim() || loading.value) return;

  const userMsg = inputMessage.value.trim();
  messages.value.push({ role: 'user', content: userMsg });
  inputMessage.value = '';
  loading.value = true;

  try {
    const res = await legacyApi.post<{ content: string; is_report?: boolean }>('/ai/chat', {
      message: userMsg,
      conversation_id: conversationId.value
    });

    if (res.code === 0) {
      messages.value.push({
        role: 'assistant',
        content: res.data.content,
        is_report: res.data.is_report
      });
    } else {
      messages.value.push({
        role: 'assistant',
        content: '❌ 处理失败：' + (res.message || '未知错误')
      });
    }
  } catch (err: any) {
    let errorMsg = '❌ 网络错误，请稍后重试';
    if (err.response) {
      if (err.response.status === 401) {
        errorMsg = '❌ 登录已过期，请重新登录';
      } else if (err.response.status === 403) {
        errorMsg = '❌ 权限不足，无法访问';
      } else if (err.response.status === 500) {
        errorMsg = '❌ 服务器内部错误';
      } else {
        errorMsg = `❌ 请求失败 (${err.response.status})`;
      }
    } else if (err.code === 'ECONNABORTED') {
      errorMsg = '❌ 请求超时，AI正在处理中，请稍后重试';
    } else if (err.request) {
      errorMsg = '❌ 无法连接到服务器，请检查网络';
    } else {
      errorMsg = '❌ 请求异常: ' + err.message;
    }
    console.error('AI聊天错误:', err);
    messages.value.push({
      role: 'assistant',
      content: errorMsg
    });
  } finally {
    loading.value = false;
  }
}

async function clearHistory() {
  try {
    await legacyApi.delete('/ai/history/' + conversationId.value);
    messages.value = [
      {
        role: 'assistant',
        content: '✅ 对话历史已清除。我现在是全新的状态，可以重新开始对话。'
      }
    ];
  } catch (err) {
    console.error('清除历史失败:', err);
  }
}

function handleKeyDown(e: KeyboardEvent) {
  if (e.key === 'Enter' && !e.shiftKey) {
    e.preventDefault();
    sendMessage();
  }
}

function formatContent(content: string) {
  if (!content) return '';
  // 先转义 HTML，再渲染轻量 Markdown，避免 AI 返回内容触发 XSS
  const escaped = content
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
  return escaped
    .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
    .replace(/\n/g, '<br>')
    .replace(
      /`([^`]+)`/g,
      '<code style="background: rgba(0,212,255,0.1);padding:2px 6px;border-radius:4px;">$1</code>'
    );
}
</script>
