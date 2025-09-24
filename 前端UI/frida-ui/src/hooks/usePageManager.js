import { useState, useRef } from 'react';
import { message } from 'antd';
import { createLogger } from '../utils/logger';

const logger = createLogger('PageManager');

export const usePageManager = (initialPages) => {
  const [pages, setPages] = useState(initialPages || [
    { 
      id: 1, 
      name: 'Frida监控', 
      type: 'frida-monitor',
      typeName: 'Frida监控',
      data: [], 
      filteredData: [],
      dataCounterRef: useRef(0)
    }
  ]);
  const [activePageId, setActivePageId] = useState(initialPages ? initialPages[0].id : 1);
  
  // 获取当前页面
  const currentPage = pages.find(page => page.id === activePageId) || pages[0];
  
  // 添加新页面
  const addPage = (newPage) => {
    logger.info('添加新页面:', newPage.name);
    setPages(prevPages => [...prevPages, newPage]);
    setActivePageId(newPage.id);
  };

  // 关闭页面
  const closePage = (pageId) => {
    logger.info('关闭页面 ID:', pageId);
    // 至少保留一个页面
    if (pages.length <= 1) {
      message.warning('至少需要保留一个页面');
      return;
    }
    
    // 如果关闭的是当前激活的页面，需要切换到另一个页面
    if (pageId === activePageId) {
      const remainingPages = pages.filter(page => page.id !== pageId);
      setActivePageId(remainingPages[0].id);
    }
    
    setPages(prevPages => prevPages.filter(page => page.id !== pageId));
  };

  // 重命名页面
  const renamePage = (pageId, newName) => {
    setPages(prevPages => 
      prevPages.map(page => 
        page.id === pageId ? { ...page, name: newName } : page
      )
    );
  };
  
  // 更新页面数据
  const updatePageData = (pageId, data, filteredData) => {
    setPages(prevPages => 
      prevPages.map(page => 
        page.id === pageId 
          ? { ...page, data, filteredData } 
          : page
      )
    );
  };

  return {
    pages,
    setPages,
    activePageId,
    setActivePageId,
    currentPage,
    addPage,
    closePage,
    renamePage,
    updatePageData
  };
};