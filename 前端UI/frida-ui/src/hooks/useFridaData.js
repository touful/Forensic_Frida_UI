import { useState, useRef, useEffect } from 'react';
import { createLogger } from '../utils/logger';

const logger = createLogger('FridaData');

export const useFridaData = (isMounted) => {
  const [fridaData, setFridaData] = useState([]);
  const [fridaFilteredData, setFridaFilteredData] = useState([]);
  const fridaDataCounter = useRef(0);
  
  // 批量数据处理相关状态
  const pendingFridaData = useRef([]);
  const fridaDataUpdateTimer = useRef(null);
  
  // 添加新数据到全局Frida监控数据状态
  const addFridaData = (fridaData) => {
    // 将数据添加到待处理队列
    pendingFridaData.current.push(fridaData);
    
    // 如果待处理数据达到100条，立即刷新
    if (pendingFridaData.current.length >= 100) {
      flushPendingFridaData();
    } else {
      // 否则设置定时器，1秒后刷新
      if (fridaDataUpdateTimer.current) {
        clearTimeout(fridaDataUpdateTimer.current);
      }
      
      // 确保定时器回调中也检查组件是否仍然挂载
      fridaDataUpdateTimer.current = setTimeout(() => {
        if (isMounted.current) {
          flushPendingFridaData();
        }
      }, 1000);
    }
  };
  
  // 刷新待处理的Frida数据
  const flushPendingFridaData = () => {
    // 检查组件是否仍然挂载
    if (!isMounted.current) return;
    
    if (pendingFridaData.current.length === 0) {
      return;
    }
    
    // 清除定时器
    if (fridaDataUpdateTimer.current) {
      clearTimeout(fridaDataUpdateTimer.current);
      fridaDataUpdateTimer.current = null;
    }
    
    // 处理所有待处理数据
    const newDataItems = pendingFridaData.current.map((fridaData, index) => {
      fridaDataCounter.current += 1;
      
      return {
        key: `${Date.now()}-${Math.random()}-${index}`,
        id: fridaDataCounter.current,
        timestamp: new Date().toISOString().slice(11, 23),
        method: fridaData.method,
        args: fridaData.args || [],
        returns: fridaData.returns || ''
      };
    });
    
    // 更新全局Frida数据状态（检查组件是否仍然挂载）
    if (isMounted.current) {
      setFridaData(prevData => {
        const updatedData = [...newDataItems, ...prevData];
        // 按ID降序排列
        updatedData.sort((a, b) => b.id - a.id);
        // 限制总数为10000条
        const limitedData = updatedData.slice(0, 10000);
        return limitedData;
      });
    }
    
    // 清空待处理数据
    pendingFridaData.current = [];
  };
  
  // 清空Frida数据
  const clearFridaData = () => {
    logger.info('清空Frida数据');
    setFridaData([]);
    setFridaFilteredData([]);
    fridaDataCounter.current = 0;
    
    // 清空待处理数据队列
    pendingFridaData.current = [];
    
    // 清理定时器
    if (fridaDataUpdateTimer.current) {
      clearTimeout(fridaDataUpdateTimer.current);
      fridaDataUpdateTimer.current = null;
    }
  };
  
  // 更新过滤后的Frida数据
  const updateFridaFilteredData = (sourceData, searchText, filterConditions) => {
    let filtered = [...sourceData];
    
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
  };

  return {
    // 状态
    fridaData,
    setFridaData,
    fridaFilteredData,
    setFridaFilteredData,
    fridaDataCounter,
    
    // 引用
    pendingFridaData,
    fridaDataUpdateTimer,
    
    // 函数
    addFridaData,
    flushPendingFridaData,
    clearFridaData,
    updateFridaFilteredData
  };
};