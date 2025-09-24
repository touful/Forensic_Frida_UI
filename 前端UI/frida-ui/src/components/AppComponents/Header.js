import React from 'react';
import { Layout, Typography, Button } from 'antd';
import { PlayCircleOutlined, StopOutlined, ClearOutlined } from '@ant-design/icons';

const { Header } = Layout;
const { Title } = Typography;

const AppHeader = ({ 
  windowSize, 
  isCapturing, 
  toggleCapture, 
  clearData, 
  connectionStatus
}) => {
  return (
    <Header style={{ 
      background: '#001529', 
      display: 'flex', 
      alignItems: 'center',
      justifyContent: 'space-between',
      padding: windowSize.width < 768 ? '0 12px' : '0 24px',
      height: 'auto',
      minHeight: 64,
      flexWrap: windowSize.width < 768 ? 'wrap' : 'nowrap'
    }}>
      <Title level={windowSize.width < 576 ? 4 : 3} style={{ color: 'white', margin: '12px 0' }}>
        APP取证极速版
      </Title>
      
      <div style={{ 
        display: 'flex', 
        alignItems: 'center', 
        gap: windowSize.width < 576 ? '4px' : '8px',
        flexWrap: 'wrap',
        margin: '12px 0'
      }}>
        <Button
          type="primary"
          icon={isCapturing ? <StopOutlined /> : <PlayCircleOutlined />}
          onClick={toggleCapture}
          size={windowSize.width < 576 ? 'small' : 'middle'}
        >
          {windowSize.width < 576 ? (isCapturing ? '停止' : '开始') : (isCapturing ? '停止捕获' : '开始捕获')}
        </Button>
        <Button
          icon={<ClearOutlined />}
          onClick={clearData}
          size={windowSize.width < 576 ? 'small' : 'middle'}
        >
          {windowSize.width < 576 ? '清空' : '清空数据'}
        </Button>
        
        <div style={{ 
          display: 'flex', 
          alignItems: 'center', 
          color: 'white', 
          marginLeft: windowSize.width < 576 ? 8 : 16,
          whiteSpace: 'nowrap',
          fontSize: windowSize.width < 576 ? '12px' : 'inherit'
        }}>
          <span>连接状态: {connectionStatus}</span>
        </div>
      </div>
    </Header>
  );
};

export default AppHeader;