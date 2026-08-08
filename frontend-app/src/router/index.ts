import { createRouter, createWebHistory } from 'vue-router';
import MainLayout from '@/layouts/MainLayout.vue';
import { useUserStore } from '@/stores/user';

const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/login', name: 'login', component: () => import('@/views/Login.vue'), meta: { title: '登录' } },
    {
      path: '/',
      component: MainLayout,
      redirect: '/dashboard',
      children: [
        {
          path: 'dashboard',
          name: 'dashboard',
          component: () => import('@/views/Dashboard.vue'),
          meta: { title: '安全概览' }
        },
        { path: 'scan', name: 'scan', component: () => import('@/views/Scan.vue'), meta: { title: '网络扫描' } },
        {
          path: 'baseline',
          name: 'baseline',
          component: () => import('@/views/Baseline.vue'),
          meta: { title: '基线排查' }
        },
        { path: 'virus', name: 'virus', component: () => import('@/views/Virus.vue'), meta: { title: '病毒查杀' } },
        { path: 'djpp', name: 'djpp', component: () => import('@/views/Djpp.vue'), meta: { title: '等保测评' } },
        {
          path: 'assistant',
          name: 'assistant',
          component: () => import('@/views/Assistant.vue'),
          meta: { title: 'AI安全助手' }
        },
        {
          path: 'situational',
          name: 'situational',
          component: () => import('@/views/Situational.vue'),
          meta: { title: '态势感知' }
        },
        {
          path: 'defense',
          name: 'defense',
          component: () => import('@/views/Defense.vue'),
          meta: { title: '自动化防御' }
        },
        { path: 'device', name: 'device', component: () => import('@/views/Device.vue'), meta: { title: '边缘设备' } },
        { path: 'users', name: 'users', component: () => import('@/views/Users.vue'), meta: { title: '用户管理' } },
        {
          path: 'playbook',
          name: 'playbook',
          component: () => import('@/views/Playbook.vue'),
          meta: { title: 'SOAR编排' }
        },
        { path: 'config', name: 'config', component: () => import('@/views/Config.vue'), meta: { title: '系统配置' } },
        {
          path: 'reports',
          name: 'reports',
          component: () => import('@/views/Reports.vue'),
          meta: { title: '报告管理' }
        }
      ]
    },
    { path: '/:pathMatch(.*)*', redirect: '/dashboard' }
  ]
});

router.beforeEach((to) => {
  document.title = to.meta.title ? `${to.meta.title as string} - 玄鉴安全智能体` : '玄鉴安全智能体';
  const userStore = useUserStore();
  if (to.path !== '/login' && !userStore.token) {
    return { path: '/login', query: { redirect: to.fullPath } };
  }
  return true;
});

export default router;
