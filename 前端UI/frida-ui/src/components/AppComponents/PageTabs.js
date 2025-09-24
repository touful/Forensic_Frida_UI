import React from 'react';
import { Tabs } from 'antd';
import PageManager from './PageManager';

const { TabPane } = Tabs;

const PageTabs = ({ 
  pages, 
  activePageId, 
  setActivePageId, 
  closePage, 
  onPageCreate, 
  windowSize 
}) => {
  return (
    <div style={{ 
      backgroundColor: '#fff', 
      padding: '0 12px',
      borderBottom: '1px solid #e8e8e8',
      display: 'flex',
      alignItems: 'center'
    }}>
      <Tabs
        activeKey={String(activePageId)}
        type="editable-card"
        onChange={(key) => setActivePageId(parseInt(key))}
        onEdit={(targetKey, action) => {
          if (action === 'add') {
            // 不再直接添加，而是通过PageManager处理
          } else if (action === 'remove') {
            closePage(parseInt(targetKey));
          }
        }}
        tabBarGutter={8}
        tabBarStyle={{ margin: 0, flex: 1 }}
        size="small"
      >
        {pages.map(page => (
          <TabPane
            tab={page.typeName}
            key={String(page.id)}
            closable={pages.length > 1 || page.id !== 1} // 保证至少有一个页面不能关闭
          />
        ))}
      </Tabs>
      <div style={{ marginLeft: 8 }}>
        <PageManager 
          onPageCreate={onPageCreate} 
          windowSize={windowSize}
        />
      </div>
    </div>
  );
};

export default PageTabs;