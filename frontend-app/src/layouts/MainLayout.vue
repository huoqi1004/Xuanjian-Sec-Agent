<template>
  <div class="app-layout">
    <!-- Sidebar -->
    <aside class="sidebar" :class="{ collapsed: sidebarCollapsed }">
      <div class="sidebar-logo">
        <div class="logo-icon">
          <svg viewBox="0 0 100 100" width="36" height="36">
            <defs>
              <linearGradient id="sLogoGrad" x1="0%" y1="0%" x2="100%" y2="100%">
                <stop offset="0%" style="stop-color: #00d4ff" />
                <stop offset="100%" style="stop-color: #7c3aed" />
              </linearGradient>
            </defs>
            <path
              d="M50 8 L88 28 L88 55 C88 75 70 90 50 96 C30 90 12 75 12 55 L12 28 Z"
              fill="none"
              stroke="url(#sLogoGrad)"
              stroke-width="3"
            />
            <circle cx="50" cy="55" r="3" fill="#00d4ff" />
          </svg>
        </div>
        <span>玄鉴安全智能体</span>
      </div>
      <div class="sidebar-menu">
        <el-menu :default-active="route.path" router :collapse="sidebarCollapsed" :collapse-transition="false">
          <el-menu-item v-for="item in visibleMenus" :key="item.path" :index="item.path">
            <el-icon><component :is="item.icon" /></el-icon>
            <span class="menu-text">{{ item.title }}</span>
          </el-menu-item>
        </el-menu>
      </div>
    </aside>

    <!-- Main -->
    <div class="main-area">
      <div class="top-header">
        <div class="header-left">
          <button class="collapse-btn" @click="sidebarCollapsed = !sidebarCollapsed">
            <el-icon :size="20"><component :is="sidebarCollapsed ? 'Expand' : 'Fold'" /></el-icon>
          </button>
          <div class="breadcrumb-area">
            <span>玄鉴安全智能体</span>
            <span> / </span>
            <span class="current">{{ route.meta.title || '' }}</span>
          </div>
        </div>
        <div class="header-right">
          <el-tooltip :content="userStore.wsConnected ? '实时连接已建立' : '实时连接断开'" placement="bottom">
            <span
              :style="{
                display: 'inline-block',
                width: '8px',
                height: '8px',
                borderRadius: '50%',
                background: userStore.wsConnected ? '#67c23a' : '#f56c6c',
                marginRight: '12px'
              }"
            ></span>
          </el-tooltip>
          <button class="notification-btn" @click="showNotifications">
            <el-icon :size="20"><Bell /></el-icon>
            <span v-if="unreadNotifications > 0" class="notification-badge">{{ unreadNotifications }}</span>
          </button>
          <el-dropdown trigger="click" @command="handleUserCommand">
            <div class="user-info">
              <div class="user-avatar">{{ userStore.username ? userStore.username.charAt(0).toUpperCase() : 'U' }}</div>
              <div>
                <div class="user-name">{{ userStore.username || '用户' }}</div>
                <div class="user-role">{{ userStore.isAdmin ? '管理员' : '操作员' }}</div>
              </div>
            </div>
            <template #dropdown>
              <el-dropdown-menu>
                <el-dropdown-item command="profile">个人信息</el-dropdown-item>
                <el-dropdown-item command="changePassword">修改密码</el-dropdown-item>
                <el-dropdown-item command="logout" divided>退出登录</el-dropdown-item>
              </el-dropdown-menu>
            </template>
          </el-dropdown>
        </div>
      </div>

      <!-- Content -->
      <div class="content-area">
        <router-view v-slot="{ Component }">
          <transition name="fade" mode="out-in">
            <component :is="Component" />
          </transition>
        </router-view>
      </div>
    </div>

    <!-- 修改密码弹窗 -->
    <el-dialog v-model="showPasswordDialog" title="修改密码" width="420px" :close-on-click-modal="false">
      <el-form :model="passwordForm" label-width="80px">
        <el-form-item label="旧密码">
          <el-input v-model="passwordForm.oldPassword" type="password" show-password placeholder="请输入旧密码" />
        </el-form-item>
        <el-form-item label="新密码">
          <el-input
            v-model="passwordForm.newPassword"
            type="password"
            show-password
            placeholder="至少8位，含字母和数字"
          />
        </el-form-item>
        <el-form-item label="确认密码">
          <el-input
            v-model="passwordForm.confirmPassword"
            type="password"
            show-password
            placeholder="请再次输入新密码"
          />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="showPasswordDialog = false">取消</el-button>
        <el-button type="primary" @click="submitPassword">确认修改</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue';
import { useRoute } from 'vue-router';
import { ElMessage, ElNotification } from 'element-plus';
import {
  Monitor,
  Search,
  Document,
  Lock,
  ChatDotRound,
  DataAnalysis,
  SetUp,
  Cpu,
  User,
  Setting,
  Aim
} from '@element-plus/icons-vue';
import { useUserStore } from '@/stores/user';
import { authApi } from '@/api';
import { wsClient } from '@/utils/ws';
import type { WsMessage } from '@/types';

const route = useRoute();
const userStore = useUserStore();

const sidebarCollapsed = ref(false);
const showPasswordDialog = ref(false);
const passwordForm = ref({ oldPassword: '', newPassword: '', confirmPassword: '' });
const unreadNotifications = ref(0);

const menus = [
  { path: '/dashboard', title: '安全概览', icon: Monitor, adminOnly: false },
  { path: '/scan', title: '网络扫描', icon: Search, adminOnly: false },
  { path: '/baseline', title: '基线排查', icon: Document, adminOnly: false },
  { path: '/virus', title: '病毒查杀', icon: Lock, adminOnly: false },
  { path: '/djpp', title: '等保测评', icon: Document, adminOnly: false },
  { path: '/assistant', title: 'AI安全助手', icon: ChatDotRound, adminOnly: false },
  { path: '/situational', title: '态势感知', icon: DataAnalysis, adminOnly: false },
  { path: '/defense', title: '自动化防御', icon: SetUp, adminOnly: false },
  { path: '/device', title: '边缘设备', icon: Cpu, adminOnly: false },
  { path: '/users', title: '用户管理', icon: User, adminOnly: true },
  { path: '/playbook', title: 'SOAR编排', icon: Aim, adminOnly: true },
  { path: '/config', title: '系统配置', icon: Setting, adminOnly: true },
  { path: '/reports', title: '报告管理', icon: Document, adminOnly: false }
];

const visibleMenus = computed(() => menus.filter((m) => !m.adminOnly || userStore.isAdmin));

let unsubscribeAlert: (() => void) | null = null;

onMounted(() => {
  unsubscribeAlert = wsClient.on('new_alert', (msg: WsMessage) => {
    unreadNotifications.value += 1;
    const data = msg.data as Record<string, unknown>;
    ElNotification({
      title: '新告警',
      message: (data.description as string) || '检测到新的安全告警',
      type: 'warning',
      duration: 5000
    });
  });
});

onUnmounted(() => {
  unsubscribeAlert?.();
});

function showNotifications() {
  ElMessage.info('您有 ' + unreadNotifications.value + ' 条未读告警，请到态势感知页处理');
}

async function submitPassword() {
  const { oldPassword, newPassword, confirmPassword } = passwordForm.value;
  if (!oldPassword || !newPassword) {
    ElMessage.warning('请填写完整');
    return;
  }
  if (newPassword !== confirmPassword) {
    ElMessage.error('两次输入的新密码不一致');
    return;
  }
  try {
    await authApi.changePassword(oldPassword, newPassword);
    ElMessage.success('密码修改成功');
    showPasswordDialog.value = false;
    passwordForm.value = { oldPassword: '', newPassword: '', confirmPassword: '' };
  } catch (e) {
    /* 错误已由拦截器提示 */
  }
}

function handleUserCommand(command: string) {
  if (command === 'logout') {
    userStore.logout();
  } else if (command === 'changePassword') {
    showPasswordDialog.value = true;
  } else if (command === 'profile') {
    ElMessage.info('当前用户: ' + userStore.username);
  }
}
</script>
