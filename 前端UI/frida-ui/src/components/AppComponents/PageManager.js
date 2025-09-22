import React, { useState } from 'react';
import { Button, Dropdown, Menu } from 'antd';
import { PlusOutlined } from '@ant-design/icons';
// 假设这些组件已存在，请根据实际路径调整
import DataTable from './DataTable'; // Frida监控的内容组件
import PermissionAnalysis from './PermissionAnalysis';
import SmartForensics from './SmartForensics';

const PageManager = ({
  onPageCreate,
  windowSize
}) => {
  // 定义页面类型选项
  const pageTypes = [
    {
      key: 'frida-monitor',
      label: 'Frida监控',
      description: '监控应用运行时的函数调用'
    },
    {
      key: 'permission-analysis',
      label: '权限分析',
      description: '分析应用的权限使用情况'
    },
    {
      key: 'smart-forensics',
      label: '智能取证（实验性功能）',
      description: '自动提取和分析应用数据'
    }
  ];

  // 快速创建页面 - 直接点击菜单项创建
  const handleQuickCreate = ({ key }) => {
    const pageType = pageTypes.find(type => type.key === key);
    if (pageType) {
      const newPage = {
        id: Date.now(), // 使用时间戳作为唯一ID
        name: `${pageType.label}`,
        type: pageType.key,
        typeName: pageType.label,
        data: [],
        filteredData: [],
        dataCounterRef: { current: 0 } // 添加数据计数器引用
      };
      onPageCreate(newPage);
    }
  };

  // 下拉菜单项
  const menu = (
    <Menu onClick={handleQuickCreate}>
      {pageTypes.map(type => (
        <Menu.Item key={type.key}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span>{type.label}</span>
            <span style={{ fontSize: '12px', color: '#999', marginLeft: '8px' }}>{type.description}</span>
          </div>
        </Menu.Item>
      ))}
    </Menu>
  );

  return (
    <div>
      <Dropdown overlay={menu} trigger={['click']} placement="bottomRight">
        <Button type="primary" icon={<PlusOutlined />}>
          添加新标签
        </Button>
      </Dropdown>
    </div>
  );
};

export default PageManager;