import { BrowserRouter as Router, Routes, Route, Navigate, Outlet, Link } from 'react-router-dom';
import { Layout, Menu, ConfigProvider } from 'antd';
import zhCN from 'antd/locale/zh_CN';
import './App.css';

// 导入页面
import Login from './pages/Login';
import Register from './pages/Register';
import Dashboard from './pages/Dashboard';
import Assets from './pages/Assets';
import Threats from './pages/Threats';
import Vulnerabilities from './pages/Vulnerabilities';
import Defense from './pages/Defense';
import Forensics from './pages/Forensics';
import Workflow from './pages/Workflow';
import AI from './pages/AI';
import ThreatIntel from './pages/ThreatIntel';
import NmapScan from './pages/NmapScan';
import NessusScan from './pages/NessusScan';
import WAFManagement from './pages/WAFManagement';
import ThreatIntelQuery from './pages/ThreatIntelQuery';
import CapeSandbox from './pages/CapeSandbox';
import ElkLogAnalysis from './pages/ElkLogAnalysis';
import LocalDefense from './pages/LocalDefense';
import AdvancedDefense from './pages/AdvancedDefense';

// 模拟登录状态
const isAuthenticated = true;

function App() {
  return (
    <ConfigProvider locale={zhCN}>
      <Router>
        <Routes>
          {/* 认证路由 */}
          <Route path="/login" element={<Login />} />
          <Route path="/register" element={<Register />} />
          
          {/* 主应用路由 */}
          <Route path="/" element={isAuthenticated ? <LayoutComponent /> : <Navigate to="/login" />}>
            <Route index element={<Dashboard />} />
            <Route path="dashboard" element={<Dashboard />} />
            <Route path="assets" element={<Assets />} />
            <Route path="threats" element={<Threats />} />
            <Route path="vulnerabilities" element={<Vulnerabilities />} />
            <Route path="defense" element={<Defense />} />
            <Route path="forensics" element={<Forensics />} />
            <Route path="workflow" element={<Workflow />} />
            <Route path="ai" element={<AI />} />
            <Route path="threat-intel" element={<ThreatIntel />} />
            <Route path="nmap-scan" element={<NmapScan />} />
            <Route path="nessus-scan" element={<NessusScan />} />
            <Route path="waf-management" element={<WAFManagement />} />
            <Route path="local-defense" element={<LocalDefense />} />
            <Route path="advanced-defense" element={<AdvancedDefense />} />
            <Route path="threat-intel-query" element={<ThreatIntelQuery />} />
            <Route path="cape-sandbox" element={<CapeSandbox />} />
            <Route path="elk-log-analysis" element={<ElkLogAnalysis />} />
          </Route>
        </Routes>
      </Router>
    </ConfigProvider>
  );
}

// 布局组件
function LayoutComponent() {
  return (
    <Layout style={{ minHeight: '100vh' }}>
      <Layout.Sider width={220} style={{ background: '#001529' }} collapsible>
        <div className="logo" style={{ height: 64, color: 'white', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 16, fontWeight: 'bold' }}>
          玄鉴安全智能体
        </div>
        <Menu
          mode="inline"
          theme="dark"
          defaultSelectedKeys={['dashboard']}
          style={{ height: '100%', borderRight: 0 }}
          items={[
            { key: 'dashboard', label: '首页', path: '/' },
            { key: 'nmap-scan', label: 'Nmap扫描', path: '/nmap-scan' },
            { key: 'nessus-scan', label: '漏洞扫描', path: '/nessus-scan' },
            { key: 'waf-management', label: 'WAF管理', path: '/waf-management' },
            { key: 'local-defense', label: '本地防御', path: '/local-defense' },
            { key: 'advanced-defense', label: '高级防御', path: '/advanced-defense' },
            { key: 'threat-intel-query', label: '威胁情报', path: '/threat-intel-query' },
            { key: 'cape-sandbox', label: 'CAPE沙箱', path: '/cape-sandbox' },
            { key: 'elk-log-analysis', label: '日志分析', path: '/elk-log-analysis' },
            { key: 'assets', label: '资产管理', path: '/assets' },
            { key: 'threats', label: '威胁管理', path: '/threats' },
            { key: 'vulnerabilities', label: '漏洞管理', path: '/vulnerabilities' },
            { key: 'defense', label: '防御规则', path: '/defense' },
            { key: 'forensics', label: '取证分析', path: '/forensics' },
            { key: 'workflow', label: '工作流', path: '/workflow' },
            { key: 'ai', label: 'AI助手', path: '/ai' },
          ].map(item => ({
            ...item,
            label: <Link to={item.path}>{item.label}</Link>
          }))}
        />
      </Layout.Sider>
      <Layout>
        <Layout.Header style={{ background: 'white', padding: 0, height: 48 }} />
        <Layout.Content style={{ margin: '24px 16px', padding: 24, background: 'white', minHeight: 280, overflow: 'auto' }}>
          <Outlet />
        </Layout.Content>
        <Layout.Footer style={{ textAlign: 'center', padding: '12px 50px' }}>
          玄鉴安全智能体 ©{new Date().getFullYear()} Created by Security Team
        </Layout.Footer>
      </Layout>
    </Layout>
  );
}

export default App;