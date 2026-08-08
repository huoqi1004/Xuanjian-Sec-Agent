import { create } from 'zustand';
import { persist } from 'zustand/middleware';
import { authApi } from '@/api';

export interface UserInfo {
  id: number;
  username: string;
  role_id: number;
  org_id: number;
  department?: string;
  role_name?: string;
  org_name?: string;
}

interface UserState {
  token: string | null;
  user: UserInfo | null;
  login: (username: string, password: string) => Promise<void>;
  fetchProfile: () => Promise<void>;
  logout: (redirect?: boolean) => void;
}

export const useUserStore = create<UserState>()(
  persist(
    (set, get) => ({
      token: null,
      user: null,
      login: async (username, password) => {
        const data = await authApi.login(username, password);
        set({ token: data.token });
        await get().fetchProfile();
      },
      fetchProfile: async () => {
        const user = (await authApi.profile()) as UserInfo;
        set({ user });
      },
      logout: (redirect = true) => {
        set({ token: null, user: null });
        if (redirect) {
          window.location.href = '/login';
        }
      }
    }),
    {
      name: 'xuanjian-react-user',
      partialize: (state) => ({ token: state.token, user: state.user })
    }
  )
);
