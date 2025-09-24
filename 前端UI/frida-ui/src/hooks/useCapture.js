import { useCallback } from 'react';
import { message } from 'antd';
import { createLogger } from '../utils/logger';

const logger = createLogger('Capture');

export const useCapture = (ws, targetPackage, selectedConfig, deviceId, hookConfigs, addFridaData) => {
  // WebSocket消息处理
  const handleWebSocketMessage = useCallback((message) => {
    if (message.type === 'frida_data') {
      // 使用全局Frida数据状态处理函数
      addFridaData(message.payload);
    } else if (message.type === 'error') {
      logger.error('WebSocket错误消息:', message.message);
      message.error(message.message);
    }
  }, [addFridaData]);

  // 启动捕获函数
  const startCapture = () => {
    if (ws.current && ws.current.readyState === WebSocket.OPEN) {
      const message = {
        type: "start_capture",
        target: targetPackage,
        configFile: selectedConfig,
        deviceId: deviceId
      };
      logger.info("发送启动捕获命令，目标应用:", targetPackage);
      ws.current.send(JSON.stringify(message));
    } else {
      const status = ws.current ? ws.current.readyState : "未初始化";
      logger.warn("WebSocket未连接，无法发送启动捕获命令，状态:", status);
      message.error("WebSocket未连接，无法发送启动捕获命令");
    }
  };

  // 发送hook配置到后端
  const sendHookConfig = () => {
    if (ws.current && ws.current.readyState === WebSocket.OPEN) {
      const message = {
        type: 'hook_config',
        configs: hookConfigs
      };
      logger.info('发送Hook配置，配置项数量:', hookConfigs.length);
      ws.current.send(JSON.stringify(message));
    } else {
      const status = ws.current ? ws.current.readyState : "未初始化";
      logger.warn("WebSocket未连接，无法发送Hook配置，状态:", status);
      message.error("WebSocket未连接，无法发送Hook配置");
    }
  };

  return {
    handleWebSocketMessage,
    startCapture,
    sendHookConfig
  };
};