import { useState } from 'react';
import { Card, Form, Input, Button, Alert, Typography } from 'antd';
import { UserOutlined, LockOutlined, MailOutlined, PhoneOutlined } from '@ant-design/icons';
import { Link } from 'react-router-dom';
import './Register.css';

const { Title } = Typography;

function Register() {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  const onFinish = (values) => {
    setLoading(true);
    setError('');
    setSuccess('');
    
    // 模拟注册请求
    setTimeout(() => {
      setLoading(false);
      setSuccess('注册成功，请登录');
      // 3秒后跳转到登录页面
      setTimeout(() => {
        window.location.href = '/login';
      }, 3000);
    }, 1500);
  };

  return (
    <div className="register-container">
      <Card className="register-card">
        <Title level={2} style={{ textAlign: 'center', marginBottom: 24 }}>玄鉴安全智能体</Title>
        <Title level={4} style={{ textAlign: 'center', marginBottom: 24 }}>注册</Title>
        
        {error && (
          <Alert
            message="注册失败"
            description={error}
            type="error"
            showIcon
            style={{ marginBottom: 24 }}
          />
        )}
        
        {success && (
          <Alert
            message="注册成功"
            description={success}
            type="success"
            showIcon
            style={{ marginBottom: 24 }}
          />
        )}
        
        <Form
          name="register"
          onFinish={onFinish}
        >
          <Form.Item
            name="username"
            rules={[
              { required: true, message: '请输入用户名!' },
              { min: 3, max: 20, message: '用户名长度应在3-20个字符之间!' }
            ]}
          >
            <Input prefix={<UserOutlined className="site-form-item-icon" />} placeholder="用户名" />
          </Form.Item>
          
          <Form.Item
            name="email"
            rules={[
              { required: true, message: '请输入邮箱!' },
              { type: 'email', message: '请输入有效的邮箱地址!' }
            ]}
          >
            <Input prefix={<MailOutlined className="site-form-item-icon" />} placeholder="邮箱" />
          </Form.Item>
          
          <Form.Item
            name="phone"
            rules={[
              { required: true, message: '请输入手机号!' },
              { pattern: /^1[3-9]\d{9}$/, message: '请输入有效的手机号!' }
            ]}
          >
            <Input prefix={<PhoneOutlined className="site-form-item-icon" />} placeholder="手机号" />
          </Form.Item>
          
          <Form.Item
            name="password"
            rules={[
              { required: true, message: '请输入密码!' },
              { min: 6, message: '密码长度至少为6个字符!' }
            ]}
          >
            <Input
              prefix={<LockOutlined className="site-form-item-icon" />}
              type="password"
              placeholder="密码"
            />
          </Form.Item>
          
          <Form.Item
            name="confirmPassword"
            dependencies={['password']}
            rules={[
              { required: true, message: '请确认密码!' },
              ({ getFieldValue }) => ({
                validator(_, value) {
                  if (!value || getFieldValue('password') === value) {
                    return Promise.resolve();
                  }
                  return Promise.reject(new Error('两次输入的密码不一致!'));
                },
              }),
            ]}
          >
            <Input
              prefix={<LockOutlined className="site-form-item-icon" />}
              type="password"
              placeholder="确认密码"
            />
          </Form.Item>
          
          <Form.Item>
            <Button
              type="primary"
              htmlType="submit"
              className="register-form-button"
              loading={loading}
              block
            >
              注册
            </Button>
            <div style={{ marginTop: 16, textAlign: 'center' }}>
              已有账号? <Link to="/login">立即登录</Link>
            </div>
          </Form.Item>
        </Form>
      </Card>
    </div>
  );
}

export default Register;