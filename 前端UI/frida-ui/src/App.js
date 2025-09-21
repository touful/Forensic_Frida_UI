import React, { useState, useEffect, useRef, useCallback } from 'react';
import { Layout, Form, message } from 'antd';
import DataFilter from './components/DataFilter';
import AppHeader from './components/AppComponents/Header';
import Sidebar from './components/AppComponents/Sidebar';
import DataTable from './components/AppComponents/DataTable';
import { DEFAULT_HOOK_CONFIG, DEFAULT_TARGET_PACKAGE, DEFAULT_DEVICE_ID } from './utils/constants';
import { useDataHandling } from './hooks/useDataHandling';
import { useWebSocket } from './hooks/useWebSocket';
import { useConfigFiles } from './hooks/useConfigFiles';
import './App.css';

const { ipcRenderer } = window.require('electron');

const App = () => {
  const [windowSize, setWindowSize] = useState({
    width: window.innerWidth,
    height: window.innerHeight
  });
  const [collapsedSider, setCollapsedSider] = useState(false);
  const [form] = Form.useForm();
  const [targetPackage, setTargetPackage] = useState(DEFAULT_TARGET_PACKAGE);
  const [deviceId, setDeviceId] = useState(DEFAULT_DEVICE_ID);
  
  const isMounted = useRef(true);
  
  // 使用拆分的hooks
  const {
    // 状态
    data,
    setData,
    filteredData,
    setFilteredData,
    searchText,
    setSearchText,
    filterConditions,
    setFilterConditions,
    
    // 函数
    addData,
    handleFilterChange,
    clearData
  } = useDataHandling(isMounted);
  
  const {
    // 状态
    ws, // 添加ws引用
    isCapturing,
    setIsCapturing,
    connectionStatus,
    setConnectionStatus,
    
    // 函数
    connectWebSocket,
    closeWebSocket
  } = useWebSocket();
  
  const {
    // 状态
    configFiles,
    setConfigFiles,
    selectedConfig,
    setSelectedConfig,
    hookConfigs,
    setHookConfigs,
    
    // 函数
    getConfigFiles,
    loadConfigFileContent
  } = useConfigFiles(ipcRenderer, isMounted);

  // 监听窗口大小变化
  useEffect(() => {
    const handleResize = () => {
      setWindowSize({
        width: window.innerWidth,
        height: window.innerHeight
      });
    };

    window.addEventListener('resize', handleResize);
    
    // 清理函数
    return () => {
      window.removeEventListener('resize', handleResize);
      
      // 标记组件已卸载
      isMounted.current = false;
    };
  }, []);

  // 监听导出数据请求
  useEffect(() => {
    const handleExportRequest = () => {
      handleExportToCSV();
    };
    
    const handleImportRequest = () => {
      handleImportFromCSV();
    };

    // 监听主进程发送的导出和导入请求
    ipcRenderer.on('request-export-data', handleExportRequest);
    ipcRenderer.on('request-import-data', handleImportRequest);

    // 清理事件监听器
    return () => {
      ipcRenderer.removeListener('request-export-data', handleExportRequest);
      ipcRenderer.removeListener('request-import-data', handleImportRequest);
    };
  }, [data]);

  // 处理导出到CSV
  const handleExportToCSV = async () => {
    try {
      const result = await ipcRenderer.invoke('export-to-csv', data);
      if (result.success) {
        message.success(`数据已导出到: ${result.filePath}`);
      } else {
        message.error(result.message);
      }
    } catch (error) {
      message.error(`导出失败: ${error.message}`);
    }
  };

  // 处理从CSV导入
  const handleImportFromCSV = async () => {
    try {
      const result = await ipcRenderer.invoke('import-from-csv');
      if (result.success) {
        // 确保数据格式正确
        const validData = result.data.map((item, index) => ({
          key: `${Date.now()}-${index}`,
          id: item.id || index + 1,
          timestamp: item.timestamp || new Date().toISOString().slice(11, 23),
          method: item.method || '',
          args: Array.isArray(item.args) ? item.args : [],
          returns: item.returns || ''
        }));
        
        setData(validData);
        setFilteredData(validData);
        message.success(`成功从 ${result.filePath} 导入 ${validData.length} 条数据`);
      } else {
        message.error(result.message);
      }
    } catch (error) {
      console.error('导入失败:', error);
      message.error(`导入失败: ${error.message || '未知错误'}`);
    }
  };

  // 初始化或刷新配置文件列表
  useEffect(() => {
    getConfigFiles();
  }, []); // 只在组件挂载时执行一次

  // 当选中的配置文件改变时，读取配置文件内容
  useEffect(() => {
    loadConfigFileContent(selectedConfig, configFiles);
  }, [selectedConfig, configFiles]);

  // WebSocket消息处理
  const handleWebSocketMessage = (message) => {
    console.log('收到WebSocket消息:', message);
    if (message.type === 'frida_data') {
      addData(message.payload);
    } else if (message.type === 'error') {
      message.error(message.message);
    } else {
      console.log('收到其他类型消息:', message);
    }
  };

  // 启动捕获函数
  const startCapture = () => {
    if (ws.current && ws.current.readyState === WebSocket.OPEN) {
      const message = {
        type: "start_capture",
        target: targetPackage,
        configFile: selectedConfig,
        deviceId: deviceId
      };
      console.log("发送启动捕获命令:", message);
      ws.current.send(JSON.stringify(message));
      console.log("发送启动捕获命令，配置文件:", selectedConfig);
    } else {
      console.log("WebSocket未连接，无法发送启动捕获命令");
      console.log("WebSocket状态:", ws.current ? ws.current.readyState : "未初始化");
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
      ws.current.send(JSON.stringify(message));
      console.log('发送Hook配置:', hookConfigs);
    } else {
      console.log("WebSocket未连接，无法发送Hook配置");
      message.error("WebSocket未连接，无法发送Hook配置");
    }
  };

  // 切换捕获状态
  const toggleCapture = () => {
    console.log("切换捕获状态，当前状态:", isCapturing);
    if (isCapturing) {
      closeWebSocket();
    } else {
      // 连接WebSocket并在连接成功后发送start_capture命令
      connectWebSocket(handleWebSocketMessage, () => {
        // 连接成功后的回调
        setTimeout(() => {
          startCapture();
        }, 100); // 稍微延迟以确保连接完全建立
      });
    }
  };

  const columns = [
    {
      title: 'ID',
      dataIndex: 'id',
      width: windowSize.width < 576 ? 60 : 80,
      ellipsis: true,
    },
    {
      title: '时间戳',
      dataIndex: 'timestamp',
      width: windowSize.width < 576 ? 80 : 120,
      ellipsis: true,
    },
    {
      title: '方法',
      dataIndex: 'method',
      className: 'method-column',
      width: windowSize.width < 576 ? 150 : 250,
      ellipsis: true,
      render: (text) => <span style={{ color: '#1890ff' }}>{text}</span>,
    },
    {
      title: '参数',
      dataIndex: 'args',
      className: 'args-column',
      width: windowSize.width < 576 ? 150 : 200,
      ellipsis: true,
      render: (args) => (
        <div>
          {args.map((arg, index) => (
            <div key={index} style={{ 
              maxWidth: 300, 
              overflow: 'hidden', 
              textOverflow: 'ellipsis',
              whiteSpace: 'nowrap'
            }}>
              {String(arg)}
            </div>
          ))}
        </div>
      ),
    },
    {
      title: '返回值',
      dataIndex: 'returns',
      className: 'returns-column',
      width: windowSize.width < 576 ? 150 : 200,
      ellipsis: true,
    }
  ];

  return (
    <Layout style={{ minHeight: '100vh' }}>
      <AppHeader 
        windowSize={windowSize}
        isCapturing={isCapturing}
        toggleCapture={toggleCapture}
        clearData={clearData}
        connectionStatus={connectionStatus}
      />
      
      <Layout>
        <Sidebar
          windowSize={windowSize}
          collapsedSider={collapsedSider}
          configFiles={configFiles}
          selectedConfig={selectedConfig}
          setSelectedConfig={setSelectedConfig}
          targetPackage={targetPackage}
          setTargetPackage={setTargetPackage}
          deviceId={deviceId}
          setDeviceId={setDeviceId}
          startCapture={startCapture}
          hookConfigs={hookConfigs}
          setHookConfigs={setHookConfigs}
          sendHookConfig={sendHookConfig}
          form={form}
          setSearchText={setSearchText}
          onFilterChange={handleFilterChange}
        />
        
        <DataTable
          windowSize={windowSize}
          data={data}
          isCapturing={isCapturing}
          filteredData={filteredData}
          columns={columns}
          searchText={searchText}
          setSearchText={setSearchText}
        />
      </Layout>
    </Layout>
  );
};

export default App;