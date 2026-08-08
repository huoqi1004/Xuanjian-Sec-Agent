/**
 * 玄鉴安全智能体前端 - ESLint 扁平配置（N-05 质量门禁）
 * Vue 3 + TypeScript + Prettier 协同
 */
import js from '@eslint/js';
import vue from 'eslint-plugin-vue';
import tseslint from 'typescript-eslint';
import prettier from 'eslint-config-prettier';
import globals from 'globals';

export default [
  { ignores: ['dist/**', 'node_modules/**', '*.config.ts', 'env.d.ts'] },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  ...vue.configs['flat/recommended'],
  {
    files: ['**/*.{ts,vue}'],
    languageOptions: {
      globals: { ...globals.browser, ...globals.node },
      parserOptions: {
        parser: tseslint.parser,
        extraFileExtensions: ['.vue'],
        sourceType: 'module'
      }
    },
    rules: {
      // 放宽：仅提示未使用变量，避免存量代码大规模改动
      '@typescript-eslint/no-unused-vars': ['warn', { argsIgnorePattern: '^_', varsIgnorePattern: '^_', caughtErrors: 'none' }],
      '@typescript-eslint/no-explicit-any': 'off',
      // env.d.ts 的 Vue 官方 shim 写法使用 DefineComponent<{}, {}, any>
      '@typescript-eslint/no-empty-object-type': 'off',
      // Vue 组件命名允许非多词（与既有视图命名一致）
      'vue/multi-word-component-names': 'off',
      // 模板指令顺序等格式交由 Prettier 处理
      'vue/max-attributes-per-line': 'off',
      'vue/singleline-html-element-content-newline': 'off',
      'vue/html-self-closing': 'off'
    }
  },
  prettier
];
