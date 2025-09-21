import { useRef, useState } from 'react';

export const useWebSocket = () => {
  const ws = useRef(null);
  const [isCapturing, setIsCapturing] = useState(false);
  const [connectionStatus, setConnectionStatus] = useState('未连接');

  // WebSocket连接函数
  const connectWebSocket = (onMessage, onConnect) => {
    try {
      // 连接到Python后端WebSocket服务器
      ws.current = new WebSocket('ws://localhost:8080');
      
      ws.current.onopen = () => {
        console.log('WebSocket连接已建立');
        setConnectionStatus('已连接');
        setIsCapturing(true);
        if (onConnect) onConnect();
      };
      
      ws.current.onmessage = (event) => {
        console.log('收到WebSocket消息:', event.data);
        try {
          const message = JSON.parse(event.data);
          if (onMessage) onMessage(message);
        } catch (e) {
          console.error('解析数据错误:', e);
        }
      };
      
      ws.current.onclose = () => {
        console.log('WebSocket连接已关闭');
        setConnectionStatus('已断开');
        setIsCapturing(false);
      };
      
      ws.current.onerror = (error) => {
        console.error('WebSocket错误:', error);
        setConnectionStatus('连接错误');
        setIsCapturing(false);
      };
    } catch (e) {
      console.error('WebSocket连接失败:', e);
      setConnectionStatus('连接失败');
    }
  };

  // 关闭WebSocket连接
  const closeWebSocket = () => {
    if (ws.current) {
      ws.current.close();
      ws.current = null;
    }
    setIsCapturing(false);
    setConnectionStatus('未连接');
  };

  return {
    ws,
    isCapturing,
    setIsCapturing,
    connectionStatus,
    setConnectionStatus,
    connectWebSocket,
    closeWebSocket
  };
};