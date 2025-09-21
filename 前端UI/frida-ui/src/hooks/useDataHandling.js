import { useState, useRef, useEffect } from 'react';

export const useDataHandling = (isMounted) => {
  const [data, setData] = useState([]);
  const [filteredData, setFilteredData] = useState([]);
  const [searchText, setSearchText] = useState('');
  const [filterConditions, setFilterConditions] = useState({});
  const dataCounter = useRef(0);
  
  // 批量数据处理相关状态
  const pendingData = useRef([]);
  const dataUpdateTimer = useRef(null);

  // 添加新数据（支持批量处理）
  const addData = (fridaData) => {
    // 检查组件是否仍然挂载
    if (!isMounted.current) return;
    
    // 将数据添加到待处理队列
    pendingData.current.push(fridaData);
    
    // 如果待处理数据达到100条，立即刷新
    if (pendingData.current.length >= 100) {
      flushPendingData();
    } else {
      // 否则设置定时器，1秒后刷新
      if (dataUpdateTimer.current) {
        clearTimeout(dataUpdateTimer.current);
      }
      
      // 确保定时器回调中也检查组件是否仍然挂载
      dataUpdateTimer.current = setTimeout(() => {
        if (isMounted.current) {
          flushPendingData();
        }
      }, 1000);
    }
  };
  
  // 刷新待处理数据
  const flushPendingData = () => {
    // 检查组件是否仍然挂载
    if (!isMounted.current) return;
    
    if (pendingData.current.length === 0) {
      return;
    }
    
    // 清除定时器
    if (dataUpdateTimer.current) {
      clearTimeout(dataUpdateTimer.current);
      dataUpdateTimer.current = null;
    }
    
    // 处理所有待处理数据
    const newDataItems = pendingData.current.map((fridaData, index) => {
      dataCounter.current += 1;
      
      return {
        key: `${Date.now()}-${Math.random()}-${index}`,
        id: dataCounter.current,
        timestamp: new Date().toISOString().slice(11, 23),
        method: fridaData.method,
        args: fridaData.args || [],
        returns: fridaData.returns || ''
      };
    });
    
    // 更新数据状态（检查组件是否仍然挂载）
    if (isMounted.current) {
      setData(prevData => {
        const updatedData = [...newDataItems, ...prevData];
        // 限制总数为10000条
        return updatedData.slice(0, 10000);
      });
    }
    
    // 清空待处理数据
    pendingData.current = [];
  };

  // 处理过滤条件变化
  const handleFilterChange = (conditions) => {
    setFilterConditions(conditions);
  };

  // 更新过滤数据
  const updateFilteredData = (sourceData = data, search = searchText, filters = filterConditions) => {
    let filtered = [...sourceData];
    
    // 应用文本搜索
    if (search) {
      filtered = filtered.filter(item =>
        item.method.includes(search) ||
        item.args.some(arg => String(arg).includes(search)) ||
        String(item.returns).includes(search)
      );
    }
    
    // 应用过滤条件
    if (filters) {
      // 方法名过滤
      if (filters.method) {
        filtered = filtered.filter(item => 
          item.method.includes(filters.method)
        );
      }
      
      // 参数过滤
      if (filters.args) {
        filtered = filtered.filter(item =>
          item.args.some(arg => String(arg).includes(filters.args))
        );
      }
      
      // 返回值过滤
      if (filters.returns) {
        filtered = filtered.filter(item =>
          String(item.returns).includes(filters.returns)
        );
      }
    }
    
    setFilteredData(filtered);
  };

  // 清空数据
  const clearData = () => {
    setData([]);
    setFilteredData([]);
    dataCounter.current = 0;
  };

  // 当数据、搜索文本或过滤条件改变时，更新过滤后的数据
  useEffect(() => {
    updateFilteredData();
  }, [data, searchText, filterConditions]);

  return {
    // 状态
    data,
    setData,
    filteredData,
    setFilteredData,
    searchText,
    setSearchText,
    filterConditions,
    setFilterConditions,
    
    // 引用
    dataCounter,
    pendingData,
    dataUpdateTimer,
    
    // 函数
    addData,
    flushPendingData,
    handleFilterChange,
    updateFilteredData,
    clearData
  };
};