import { defineStore } from 'pinia';
import type { UserInfo } from '@/types';

const TOKEN_KEY = 'xuanjian_token';
const USER_KEY = 'xuanjian_user';

/** 用户会话 Store（localStorage 持久化，键名与旧版保持一致便于平滑迁移） */
export const useUserStore = defineStore('user', {
  state: () => ({
    token: localStorage.getItem(TOKEN_KEY) || '',
    user: JSON.parse(localStorage.getItem(USER_KEY) || 'null') as UserInfo | null,
    wsConnected: false
  }),
  getters: {
    isAdmin: (state) => state.user?.role_name === 'admin' || state.user?.role_id === 1,
    username: (state) => state.user?.username || ''
  },
  actions: {
    setAuth(token: string, user: UserInfo) {
      this.token = token;
      this.user = user;
      localStorage.setItem(TOKEN_KEY, token);
      localStorage.setItem(USER_KEY, JSON.stringify(user));
    },
    setUser(user: UserInfo) {
      this.user = user;
      localStorage.setItem(USER_KEY, JSON.stringify(user));
    },
    logout(redirect = true) {
      this.token = '';
      this.user = null;
      localStorage.removeItem(TOKEN_KEY);
      localStorage.removeItem(USER_KEY);
      if (redirect) {
        window.location.href = '/login.html';
      }
    }
  }
});
