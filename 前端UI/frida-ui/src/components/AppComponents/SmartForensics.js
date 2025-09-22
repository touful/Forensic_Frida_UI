import React, { useState, useEffect } from 'react';
import { Card, Button, Space, Typography, Menu, Dropdown } from 'antd';
import { PlayCircleOutlined, ReloadOutlined } from '@ant-design/icons';

const { Title } = Typography;

const SmartForensics = ({ windowSize }) => {
  const [iframeKey, setIframeKey] = useState(0);
  const [isServiceAvailable, setIsServiceAvailable] = useState(true);
  const [isLoading, setIsLoading] = useState(true);

  // 检查服务是否可用
  useEffect(() => {
    const checkService = async () => {
      try {
        // 尝试访问服务的根路径，设置较短的超时
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 3000);

        await fetch('http://localhost:7860/', {
          method: 'HEAD',
          mode: 'no-cors',
          signal: controller.signal
        });

        clearTimeout(timeoutId);
        setIsServiceAvailable(true);
        setIsLoading(false);
      } catch (error) {
        setIsServiceAvailable(false);
        setIsLoading(false);
      }
    };

    checkService();
  }, []);

  // 刷新iframe
  const refreshIframe = () => {
    setIframeKey(prevKey => prevKey + 1);
    setIsLoading(true);
    // 重置加载状态
    setTimeout(() => setIsLoading(false), 1000);
  };

  const menu = (
    <Menu>
      <Menu.Item key="refresh" icon={<ReloadOutlined />} onClick={refreshIframe}>
        刷新页面
      </Menu.Item>
      <Menu.Item key="open" icon={<PlayCircleOutlined />} onClick={() => window.open('http://localhost:7860', '_blank')}>
        在浏览器中打开
      </Menu.Item>
    </Menu>
  );

  return (
    <Dropdown overlay={menu} trigger={['contextMenu']} style={{ height: '100%' }}>
      <div style={{ 
        padding: windowSize.width < 576 ? '12px' : '24px', 
        height: '100%', 
        display: 'flex', 
        flexDirection: 'column',
        cursor: 'context-menu'
      }}>
        {isServiceAvailable ? (
          <div style={{ 
            flex: '1 1 auto', 
            border: '1px solid #e8e8e8',
            borderRadius: 4,
            overflow: 'hidden',
            minHeight: 0,
            height: '100%'
          }}>
            <iframe
              key={iframeKey}
              src="http://localhost:7860"
              style={{
                width: '100%',
                height: '100%',
                border: 'none'
              }}
              title="智能取证服务"
              onLoad={() => setIsLoading(false)}
              onError={(e) => {
                console.error('iframe加载失败:', e);
                setIsServiceAvailable(false);
              }}
            />
          </div>
        ) : (
          <div style={{
            flex: '1 1 auto',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            border: '1px solid #e8e8e8',
            borderRadius: 4,
            padding: '24px',
            textAlign: 'center',
            color: '#ff4d4f'
          }}>
            <div>
              <Title level={4} style={{ color: '#ff4d4f' }}>智能取证（实验性）功能未成功启动</Title>
              <div style={{ marginTop: 16 }}>
                请确保本地取证服务已在端口 7860 上运行
              </div>
            </div>
          </div>
        )}
      </div>
    </Dropdown>
  );
};

export default SmartForensics;