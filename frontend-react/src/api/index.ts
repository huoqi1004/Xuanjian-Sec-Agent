import { requestData } from './http';

export const authApi = {
  login: (username: string, password: string) =>
    requestData<{ token: string; user?: unknown }>({ method: 'POST', url: '/auth/login', data: { username, password } }),
  profile: () => requestData<unknown>({ method: 'GET', url: '/auth/profile' }),
  register: (data: { username: string; password: string; role_id?: number; department?: string }) =>
    requestData<unknown>({ method: 'POST', url: '/auth/register', data }),
  changePassword: (old_password: string, new_password: string) =>
    requestData<null>({ method: 'PUT', url: '/auth/password', data: { old_password, new_password } })
};

export const agentApi = {
  run: (task: string) => requestData<unknown>({ method: 'POST', url: '/ai/agent/run', data: { task } }),
  confirm: (confirmation_id: string, decision: string) =>
    requestData<unknown>({ method: 'POST', url: '/ai/agent/confirm', data: { confirmation_id, decision } }),
  pending: () => requestData<unknown[]>({ method: 'GET', url: '/ai/agent/pending' }),
  tools: () => requestData<unknown[]>({ method: 'GET', url: '/ai/agent/tools' }),
  plan: (task: string) => requestData<unknown>({ method: 'GET', url: '/ai/agent/plan', params: { task } })
};

// 以下模块桩：C3-C10 逐个填充
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export const scanApi = {} as any;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export const baselineApi = {} as any;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export const virusApi = {} as any;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export const situationalApi = {} as any;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export const djppApi = {} as any;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export const defenseApi = {} as any;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export const deviceApi = {} as any;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export const userApi = {} as any;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export const playbookApi = {} as any;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export const configApi = {} as any;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export const reportsApi = {} as any;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export const aiApi = {} as any;
