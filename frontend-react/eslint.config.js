/**
 * 玄鉴安全智能体前端 React - ESLint 扁平配置（N-25 质量门禁）
 * React 18 + TypeScript + Prettier 协同
 */
import js from '@eslint/js';
import tseslint from 'typescript-eslint';
import reactHooks from 'eslint-plugin-react-hooks';
import reactRefresh from 'eslint-plugin-react-refresh';
import prettier from 'eslint-config-prettier';
import globals from 'globals';

export default [
  { ignores: ['dist/**', 'node_modules/**'] },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    files: ['src/**/*.{ts,tsx}'],
    languageOptions: {
      globals: { ...globals.browser },
      sourceType: 'module'
    },
    plugins: {
      'react-hooks': reactHooks,
      'react-refresh': reactRefresh
    },
    rules: {
      ...reactHooks.configs.flat.recommended.rules,
      // v7 新增 experimental 规则：对页面桩（demo 数据/loadData 模式/函数声明提升）误报过多，关闭
      'react-hooks/purity': 'off',
      'react-hooks/set-state-in-effect': 'off',
      'react-hooks/immutability': 'off',
      // 组件与常量同文件导出（页面桩），避免误报
      'react-refresh/only-export-components': 'off',
      // shadcn/ui 空接口扩展写法（与 Vue 版一致关闭）
      '@typescript-eslint/no-empty-object-type': 'off',
      // 存量页面桩有少量 any，放宽为提示，不阻断门禁
      '@typescript-eslint/no-explicit-any': 'warn',
      // 未使用变量由 tsc(noUnusedLocals) 兜底，此处仅提示
      '@typescript-eslint/no-unused-vars': [
        'warn',
        { argsIgnorePattern: '^_', varsIgnorePattern: '^_', caughtErrors: 'none' }
      ]
    }
  },
  prettier
];
