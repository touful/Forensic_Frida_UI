import React, { useState, useEffect, useRef } from 'react';
import { Form, Layout } from 'antd';
import AppHeader from './components/AppComponents/Header';
import Sidebar from './components/AppComponents/Sidebar';
import DataTable from './components/AppComponents/DataTable';
import PageTabs from './components/AppComponents/PageTabs';
import { DEFAULT_TARGET_PACKAGE, DEFAULT_DEVICE_ID } from './utils/constants';
import { useDataHandling } from './hooks/useDataHandling';
import { useWebSocket } from './hooks/useWebSocket';
import { useConfigFiles } from './hooks/useConfigFiles';
import { useFridaData } from './hooks/useFridaData';
import { usePageManager } from './hooks/usePageManager';
import { useCSVHandler } from './hooks/useCSVHandler';
import { useCapture } from './hooks/useCapture';
import { createLogger } from './utils/logger';
import './App.css';

const { ipcRenderer } = window.require('electron');
const logger = createLogger('App');

const App = () => {
  const [windowSize, setWindowSize] = useState({
    width: window.innerWidth,
    height: window.innerHeight
  });
  const [collapsedSider, setCollapsedSider] = useState(false);
  const [form] = Form.useForm();
  const [targetPackage, setTargetPackage] = useState(DEFAULT_TARGET_PACKAGE);
  const [deviceId, setDeviceId] = useState(DEFAULT_DEVICE_ID);
  
  // 添加缺失的模态框状态变量
  const [selectedRecord, setSelectedRecord] = useState(null);
  const [detailModalVisible, setDetailModalVisible] = useState(false);
  const [modalWidth, setModalWidth] = useState(800);
  
  const isMounted = useRef(true);
  
  // 使用拆分的hooks
  const {
    searchText,
    setSearchText,
    filterConditions,
    setFilterConditions,
    clearData: clearGeneralData
  } = useDataHandling(isMounted);
  
  const {
    fridaData,
    setFridaData,
    fridaFilteredData,
    setFridaFilteredData,
    addFridaData
  } = useFridaData(isMounted);
  
  const {
    pages,
    setPages,
    activePageId,
    setActivePageId,
    currentPage,
    addPage,
    closePage
  } = usePageManager();
  
  const {
    handleExportToCSV,
    handleImportFromCSV,
    exportCSV,
    importCSV
  } = useCSVHandler(ipcRenderer);
  
  const {
    ws,
    isCapturing,
    setIsCapturing,
    connectionStatus,
    setConnectionStatus,
    connectWebSocket,
    closeWebSocket
  } = useWebSocket();
  
  const {
    configFiles,
    setConfigFiles,
    selectedConfig,
    setSelectedConfig,
    hookConfigs,
    setHookConfigs,
    getConfigFiles,
    loadConfigFileContent
  } = useConfigFiles(ipcRenderer, isMounted);
  
  const {
    handleWebSocketMessage,
    startCapture,
    sendHookConfig
  } = useCapture(ws, targetPackage, selectedConfig, deviceId, hookConfigs, addFridaData);

  // 添加调试日志
  useEffect(() => {
    // 移除不必要的日志输出
  }, [detailModalVisible]);
  
  // 当fridaData、searchText或filterConditions改变时，更新fridaFilteredData
  useEffect(() => {
    let filtered = [...fridaData];
    
    // 应用文本搜索
    if (searchText) {
      filtered = filtered.filter(item =>
        item.method.includes(searchText) ||
        item.args.some(arg => String(arg).includes(searchText)) ||
        String(item.returns).includes(searchText)
      );
    }
    
    // 应用过滤条件
    if (filterConditions) {
      // 方法名过滤
      if (filterConditions.method) {
        filtered = filtered.filter(item => 
          item.method.includes(filterConditions.method)
        );
      }
      
      // 参数过滤
      if (filterConditions.args) {
        filtered = filtered.filter(item =>
          item.args.some(arg => String(arg).includes(filterConditions.args))
        );
      }
      
      // 返回值过滤
      if (filterConditions.returns) {
        filtered = filtered.filter(item =>
          String(item.returns).includes(filterConditions.returns)
        );
      }
    }
    
    setFridaFilteredData(filtered);
  }, [fridaData, searchText, filterConditions, setFridaFilteredData]);
  
  // 清空数据（修复核心：直接更新useDataHandling状态并同步页面）
  const clearData = () => {
    logger.info('清空所有数据');
    // 1. 立即清空useDataHandling管理的数据状态
    clearGeneralData();

    // 2. 清空全局Frida数据状态
    setFridaData([]);
    setFridaFilteredData([]);

    // 3. 同时更新所有页面的数据存储
    setPages(prevPages => 
      prevPages.map(page => {
        // 重置Frida监控页面数据
        if (page.type === 'frida-monitor') {
          return { 
            ...page, 
            data: [], 
            filteredData: []
          };
        }
        // 重置其他类型页面数据
        return { 
          ...page, 
          data: [], 
          filteredData: []
        };
      })
    );
  };

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
  }, []);

  // 初始化或刷新配置文件列表
  useEffect(() => {
    getConfigFiles();
  }, []); // 只在组件挂载时执行一次

  // 当选中的配置文件改变时，读取配置文件内容
  useEffect(() => {
    if (selectedConfig) {
      loadConfigFileContent(selectedConfig, configFiles);
    }
  }, [selectedConfig, configFiles, loadConfigFileContent]);

  // 当hook配置改变时，自动发送到后端
  useEffect(() => {
    if (isCapturing && hookConfigs.length > 0) {
      // 添加一个小延迟，避免频繁发送
      const timer = setTimeout(() => {
        sendHookConfig();
      }, 500);
      
      return () => clearTimeout(timer);
    }
  }, [hookConfigs, isCapturing, sendHookConfig]);

  // 切换捕获状态
  const toggleCapture = () => {
    logger.info("切换捕获状态，当前状态:", isCapturing);
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

  // 添加新页面 (由 PageManager 调用)
  const handleCreatePage = (newPage) => {
    logger.info('创建新页面:', newPage.name);
    addPage(newPage);
  };

  // 关闭页面
  const handleClosePage = (pageId) => {
    logger.info('关闭页面 ID:', pageId);
    closePage(pageId);
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
          onFilterChange={setFilterConditions} // 传递过滤条件设置函数
        />
        
        <Layout>
          <PageTabs
            pages={pages}
            activePageId={activePageId}
            setActivePageId={setActivePageId}
            closePage={handleClosePage}
            onPageCreate={handleCreatePage}
            windowSize={windowSize}
          />
          
          <DataTable
            windowSize={windowSize}
            data={currentPage.type === 'frida-monitor' ? fridaData : currentPage.data}
            filteredData={currentPage.type === 'frida-monitor' ? fridaFilteredData : currentPage.filteredData}
            isCapturing={isCapturing}
            searchText={searchText}
            setSearchText={setSearchText}
            columns={columns || []}
            pageType={currentPage?.type || 'frida-monitor'}
            // 传递详细信息模态框相关状态和函数
            selectedRecord={selectedRecord}
            setSelectedRecord={setSelectedRecord}
            detailModalVisible={detailModalVisible}
            setDetailModalVisible={setDetailModalVisible}
            modalWidth={modalWidth}
            setModalWidth={setModalWidth}
          />
        </Layout>
      </Layout>
    </Layout>
  );
};

export default App;