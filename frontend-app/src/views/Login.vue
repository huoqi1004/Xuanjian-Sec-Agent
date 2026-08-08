<template>
  <div class="login-container">
    <div class="bg-particles">
      <span v-for="i in 20" :key="i" class="particle"></span>
    </div>
    <div class="grid-bg"></div>
    <div class="glow-orb glow-orb-1"></div>
    <div class="glow-orb glow-orb-2"></div>
    <div class="glow-orb glow-orb-3"></div>

    <div class="login-card">
      <div class="logo-section">
        <div class="logo-icon">
          <svg viewBox="0 0 100 100">
            <defs>
              <linearGradient id="logoGrad" x1="0%" y1="0%" x2="100%" y2="100%">
                <stop offset="0%" style="stop-color: #00d4ff" />
                <stop offset="100%" style="stop-color: #7c3aed" />
              </linearGradient>
            </defs>
            <path
              d="M50 8 L88 28 L88 55 C88 75 70 90 50 96 C30 90 12 75 12 55 L12 28 Z"
              fill="none"
              stroke="url(#logoGrad)"
              stroke-width="2.5"
              filter="url(#glow)"
            />
            <circle cx="50" cy="55" r="3" fill="#00d4ff" />
          </svg>
        </div>
        <h1 class="logo-title">玄鉴安全智能体</h1>
        <p class="logo-subtitle">多引擎协同安全评估系统</p>
      </div>

      <el-form ref="loginFormRef" :model="loginForm" :rules="loginRules" class="login-form" @keyup.enter="handleLogin">
        <el-form-item label="用户名" prop="username">
          <el-input v-model="loginForm.username" placeholder="请输入用户名" prefix-icon="User" size="large" />
        </el-form-item>
        <el-form-item label="密码" prop="password">
          <el-input
            v-model="loginForm.password"
            type="password"
            placeholder="请输入密码"
            prefix-icon="Lock"
            size="large"
            show-password
          />
        </el-form-item>

        <div class="login-options">
          <el-checkbox v-model="loginForm.remember">记住我</el-checkbox>
          <a class="forgot-link" @click="showForgotTip">忘记密码?</a>
        </div>

        <el-form-item>
          <button type="button" class="login-btn" :disabled="loading" @click="handleLogin">
            {{ loading ? '登录中...' : '登 录' }}
          </button>
        </el-form-item>
      </el-form>

      <div class="version-info">v2.0.0 | Powered by Multi-Engine AI Security</div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import { ElMessage, type FormInstance, type FormRules } from 'element-plus';
import { useUserStore } from '@/stores/user';
import { authApi } from '@/api';

const route = useRoute();
const router = useRouter();
const userStore = useUserStore();

const loginFormRef = ref<FormInstance>();
const loading = ref(false);
const loginForm = reactive({ username: '', password: '', remember: false });

const loginRules: FormRules = {
  username: [
    { required: true, message: '请输入用户名', trigger: 'blur' },
    { min: 3, max: 20, message: '用户名长度在3到20个字符', trigger: 'blur' }
  ],
  password: [
    { required: true, message: '请输入密码', trigger: 'blur' },
    { min: 6, max: 32, message: '密码长度在6到32个字符', trigger: 'blur' }
  ]
};

onMounted(() => {
  // 已登录则直接跳转
  if (userStore.token) {
    router.replace((route.query.redirect as string) || '/dashboard');
    return;
  }
  const saved = localStorage.getItem('xuanjian_remember');
  if (saved) {
    try {
      const data = JSON.parse(saved);
      loginForm.username = data.username || '';
      loginForm.password = data.password || '';
      loginForm.remember = true;
    } catch (e) {
      /* ignore */
    }
  }
});

async function handleLogin() {
  if (!loginFormRef.value) return;
  try {
    await loginFormRef.value.validate();
  } catch (e) {
    return;
  }

  loading.value = true;
  try {
    const { token, user } = await authApi.login(loginForm.username, loginForm.password);
    userStore.setAuth(token, user);

    if (loginForm.remember) {
      localStorage.setItem(
        'xuanjian_remember',
        JSON.stringify({
          username: loginForm.username,
          password: loginForm.password
        })
      );
    } else {
      localStorage.removeItem('xuanjian_remember');
    }

    ElMessage.success('登录成功，正在跳转...');
    setTimeout(() => {
      router.replace((route.query.redirect as string) || '/dashboard');
    }, 500);
  } catch (error) {
    ElMessage.error('登录失败，请检查用户名和密码');
  } finally {
    loading.value = false;
  }
}

function showForgotTip() {
  ElMessage.info('请联系系统管理员重置密码');
}
</script>

<style scoped>
* {
  margin: 0;
  padding: 0;
  box-sizing: border-box;
}
.login-container {
  width: 100vw;
  height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  position: relative;
  background: linear-gradient(135deg, #0a0a1a 0%, #1a1a2e 50%, #16213e 100%);
}
.bg-particles {
  position: absolute;
  top: 0;
  left: 0;
  width: 100%;
  height: 100%;
  overflow: hidden;
  z-index: 0;
}
.particle {
  position: absolute;
  width: 2px;
  height: 2px;
  background: #00d4ff;
  border-radius: 50%;
  opacity: 0;
  animation: float-particle 6s infinite;
}
.particle:nth-child(1) {
  left: 10%;
  top: 20%;
  animation-delay: 0s;
  animation-duration: 8s;
}
.particle:nth-child(2) {
  left: 20%;
  top: 80%;
  animation-delay: 1s;
  animation-duration: 6s;
}
.particle:nth-child(3) {
  left: 30%;
  top: 40%;
  animation-delay: 2s;
  animation-duration: 7s;
}
.particle:nth-child(4) {
  left: 40%;
  top: 60%;
  animation-delay: 0.5s;
  animation-duration: 9s;
}
.particle:nth-child(5) {
  left: 50%;
  top: 30%;
  animation-delay: 1.5s;
  animation-duration: 5s;
}
.particle:nth-child(6) {
  left: 60%;
  top: 70%;
  animation-delay: 3s;
  animation-duration: 8s;
}
.particle:nth-child(7) {
  left: 70%;
  top: 10%;
  animation-delay: 2.5s;
  animation-duration: 6s;
}
.particle:nth-child(8) {
  left: 80%;
  top: 50%;
  animation-delay: 0.8s;
  animation-duration: 7s;
}
.particle:nth-child(9) {
  left: 90%;
  top: 90%;
  animation-delay: 1.2s;
  animation-duration: 9s;
}
.particle:nth-child(10) {
  left: 15%;
  top: 55%;
  animation-delay: 2.2s;
  animation-duration: 6s;
}
.particle:nth-child(11) {
  left: 25%;
  top: 15%;
  animation-delay: 3.5s;
  animation-duration: 8s;
}
.particle:nth-child(12) {
  left: 35%;
  top: 85%;
  animation-delay: 0.3s;
  animation-duration: 7s;
}
.particle:nth-child(13) {
  left: 45%;
  top: 25%;
  animation-delay: 1.8s;
  animation-duration: 5s;
}
.particle:nth-child(14) {
  left: 55%;
  top: 65%;
  animation-delay: 2.8s;
  animation-duration: 9s;
}
.particle:nth-child(15) {
  left: 65%;
  top: 45%;
  animation-delay: 0.6s;
  animation-duration: 6s;
}
.particle:nth-child(16) {
  left: 75%;
  top: 75%;
  animation-delay: 1.1s;
  animation-duration: 8s;
}
.particle:nth-child(17) {
  left: 85%;
  top: 35%;
  animation-delay: 2.1s;
  animation-duration: 7s;
}
.particle:nth-child(18) {
  left: 95%;
  top: 55%;
  animation-delay: 3.2s;
  animation-duration: 5s;
}
.particle:nth-child(19) {
  left: 5%;
  top: 45%;
  animation-delay: 0.9s;
  animation-duration: 9s;
}
.particle:nth-child(20) {
  left: 55%;
  top: 5%;
  animation-delay: 2.6s;
  animation-duration: 6s;
}
@keyframes float-particle {
  0% {
    opacity: 0;
    transform: translateY(0) scale(1);
  }
  20% {
    opacity: 0.8;
  }
  80% {
    opacity: 0.3;
  }
  100% {
    opacity: 0;
    transform: translateY(-100px) scale(2);
  }
}
.grid-bg {
  position: absolute;
  top: 0;
  left: 0;
  width: 100%;
  height: 100%;
  background-image:
    linear-gradient(rgba(0, 212, 255, 0.03) 1px, transparent 1px),
    linear-gradient(90deg, rgba(0, 212, 255, 0.03) 1px, transparent 1px);
  background-size: 50px 50px;
  z-index: 0;
}
.glow-orb {
  position: absolute;
  border-radius: 50%;
  filter: blur(80px);
  z-index: 0;
}
.glow-orb-1 {
  width: 300px;
  height: 300px;
  background: rgba(0, 212, 255, 0.15);
  top: -100px;
  right: -50px;
  animation: pulse-glow 4s ease-in-out infinite;
}
.glow-orb-2 {
  width: 250px;
  height: 250px;
  background: rgba(124, 58, 237, 0.15);
  bottom: -80px;
  left: -50px;
  animation: pulse-glow 5s ease-in-out infinite reverse;
}
.glow-orb-3 {
  width: 200px;
  height: 200px;
  background: rgba(0, 212, 255, 0.08);
  top: 50%;
  left: 50%;
  transform: translate(-50%, -50%);
  animation: pulse-glow 6s ease-in-out infinite;
}
@keyframes pulse-glow {
  0%,
  100% {
    opacity: 0.5;
    transform: scale(1);
  }
  50% {
    opacity: 1;
    transform: scale(1.1);
  }
}
.login-card {
  position: relative;
  z-index: 10;
  width: 420px;
  padding: 50px 40px;
  background: rgba(22, 33, 62, 0.85);
  border: 1px solid rgba(0, 212, 255, 0.2);
  border-radius: 16px;
  backdrop-filter: blur(20px);
  box-shadow:
    0 0 30px rgba(0, 212, 255, 0.1),
    0 0 60px rgba(0, 212, 255, 0.05),
    inset 0 1px 0 rgba(255, 255, 255, 0.05);
}
.login-card::before {
  content: '';
  position: absolute;
  top: -1px;
  left: 20%;
  right: 20%;
  height: 2px;
  background: linear-gradient(90deg, transparent, #00d4ff, transparent);
  border-radius: 2px;
}
.logo-section {
  text-align: center;
  margin-bottom: 40px;
}
.logo-icon {
  width: 80px;
  height: 80px;
  margin: 0 auto 20px;
  position: relative;
}
.logo-icon svg {
  width: 100%;
  height: 100%;
}
.logo-title {
  font-size: 28px;
  font-weight: 700;
  background: linear-gradient(135deg, #00d4ff, #7c3aed);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  background-clip: text;
  margin-bottom: 8px;
  letter-spacing: 2px;
}
.logo-subtitle {
  font-size: 13px;
  color: rgba(255, 255, 255, 0.4);
  letter-spacing: 4px;
}
.login-form .el-form-item {
  margin-bottom: 24px;
}
.login-form .el-input__wrapper {
  background: rgba(10, 10, 26, 0.6) !important;
  border: 1px solid rgba(0, 212, 255, 0.15) !important;
  border-radius: 8px !important;
  box-shadow: none !important;
  padding: 4px 15px !important;
  height: 46px !important;
  transition: all 0.3s ease;
}
.login-form .el-input__wrapper:hover {
  border-color: rgba(0, 212, 255, 0.3) !important;
}
.login-form .el-input__wrapper.is-focus {
  border-color: #00d4ff !important;
  box-shadow: 0 0 15px rgba(0, 212, 255, 0.15) !important;
}
.login-form .el-input__inner {
  color: #e0e0e0 !important;
  font-size: 14px;
}
.login-form .el-input__inner::placeholder {
  color: rgba(255, 255, 255, 0.3) !important;
}
.login-form .el-input__prefix .el-icon {
  color: rgba(0, 212, 255, 0.6) !important;
  font-size: 16px;
}
.login-form .el-form-item__label {
  color: rgba(255, 255, 255, 0.7) !important;
  font-size: 13px;
  padding-bottom: 6px !important;
}
.login-form .el-form-item__error {
  padding-top: 4px;
}
.login-btn {
  width: 100%;
  height: 46px;
  font-size: 16px;
  font-weight: 600;
  letter-spacing: 4px;
  border: none;
  border-radius: 8px;
  background: linear-gradient(135deg, #00d4ff, #7c3aed);
  color: #fff;
  cursor: pointer;
  position: relative;
  overflow: hidden;
  transition: all 0.3s ease;
}
.login-btn:hover {
  transform: translateY(-1px);
  box-shadow: 0 5px 25px rgba(0, 212, 255, 0.3);
}
.login-btn:active {
  transform: translateY(0);
}
.login-btn::after {
  content: '';
  position: absolute;
  top: -50%;
  left: -50%;
  width: 200%;
  height: 200%;
  background: linear-gradient(transparent, rgba(255, 255, 255, 0.1), transparent);
  transform: rotate(45deg);
  animation: btn-shine 3s infinite;
}
@keyframes btn-shine {
  0% {
    transform: translateX(-100%) rotate(45deg);
  }
  100% {
    transform: translateX(100%) rotate(45deg);
  }
}
.login-options {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 24px;
}
.login-options .el-checkbox__label {
  color: rgba(255, 255, 255, 0.5) !important;
  font-size: 13px;
}
.login-options .el-checkbox__inner {
  background: rgba(10, 10, 26, 0.6) !important;
  border-color: rgba(0, 212, 255, 0.3) !important;
}
.login-options .el-checkbox__input.is-checked .el-checkbox__inner {
  background: #00d4ff !important;
  border-color: #00d4ff !important;
}
.forgot-link {
  color: rgba(0, 212, 255, 0.7);
  font-size: 13px;
  text-decoration: none;
  cursor: pointer;
  transition: color 0.3s;
}
.forgot-link:hover {
  color: #00d4ff;
}
.version-info {
  text-align: center;
  margin-top: 30px;
  color: rgba(255, 255, 255, 0.2);
  font-size: 12px;
}
</style>
