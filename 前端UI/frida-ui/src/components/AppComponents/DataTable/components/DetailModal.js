import React, { useState } from 'react';
import { Modal, Tabs, Descriptions, Tag, Typography, Dropdown, Menu, message } from 'antd';
import { convertToHex, convertToAscii, isJSON, formatJSON } from '../utils';
import CollapsibleJSON from './CollapsibleJSON';

const { TabPane } = Tabs;
const { Text, Paragraph } = Typography;

// 解析可能的数组数据
const parseArrayData = (data) => {
  // 如果已经是数组，直接返回
  if (Array.isArray(data)) {
    return data;
  }
  
  // 如果是字符串，尝试解析为数组
  if (typeof data === 'string') {
    try {
      // 尝试解析标准JSON数组
      const parsed = JSON.parse(data);
      if (Array.isArray(parsed)) {
        return parsed;
      }
    } catch (e) {
      // 不是JSON数组，继续尝试其他格式
    }
    
    // 尝试解析不带引号的数组格式，如：[value1, value2, value3]
    // 这种格式在Frida hook中比较常见
    const arrayMatch = data.match(/^\[(.*)\]$/);
    if (arrayMatch) {
      try {
        // 分割数组元素
        const elements = arrayMatch[1].split(',').map(item => item.trim());
        return elements;
      } catch (e) {
        // 解析失败，返回原始数据
      }
    }
  }
  
  // 如果无法解析为数组，包装成单元素数组
  return [data];
};

// 可右键菜单的文本组件
const ContextMenuText = ({ children, text }) => {
  const [selectedText, setSelectedText] = useState('');

  const handleContextMenu = (e) => {
    const selection = window.getSelection().toString();
    setSelectedText(selection);
  };

  const handleCopy = () => {
    if (selectedText) {
      navigator.clipboard.writeText(selectedText);
      message.success('已复制到剪贴板');
    }
  };

  const handleSmartDecode = () => {
    if (selectedText) {
      // TODO: 实现智能解码功能
      message.info('智能解码功能待实现');
    }
  };

  const menu = (
    <Menu>
      <Menu.Item key="copy" onClick={handleCopy}>
        复制
      </Menu.Item>
      <Menu.Item key="decode" onClick={handleSmartDecode}>
        智能解码
      </Menu.Item>
    </Menu>
  );

  return (
    <Dropdown 
      overlay={menu} 
      trigger={['contextMenu']}
      overlayStyle={{ minWidth: '120px' }}
    >
      <div onContextMenu={handleContextMenu} style={{ display: 'inline-block' }}>
        {children}
      </div>
    </Dropdown>
  );
};

// 渲染参数列表
const renderArgsList = (args, converter = null) => {
  if (!args || args.length === 0) {
    return '无参数';
  }
  
  // 解析参数为数组
  const parsedArgs = parseArrayData(args);
  
  return (
    <div>
      {parsedArgs.map((arg, index) => {
        const formattedArg = converter ? converter(arg) : String(arg);
        const isJsonData = isJSON(formattedArg);
        
        // 检查是否为JSON且包含$className键
        let hasClassName = false;
        let parsedJsonData = null;
        if (isJsonData) {
          try {
            parsedJsonData = JSON.parse(formattedArg);
            hasClassName = parsedJsonData.hasOwnProperty('$className');
          } catch (e) {
            // 解析失败，保持hasClassName为false
          }
        }
        
        return (
          <div key={index} style={{ marginBottom: '8px' }}>
            {hasClassName ? `参数${index + 1}（内部属性遍历）：` : `参数${index + 1}：`}
            {isJsonData ? (
              <div style={{
                background: '#f5f5f5',
                padding: '8px',
                borderRadius: '4px',
                margin: '4px 0'
              }}>
                <CollapsibleJSON data={JSON.parse(formattedArg)} />
              </div>
            ) : (
              <ContextMenuText text={formattedArg}>
                <span>{formattedArg}</span>
              </ContextMenuText>
            )}
          </div>
        );
      })}
    </div>
  );
};

// 渲染返回值
const renderReturnValue = (returns, converter = null) => {
  if (returns === undefined || returns === null) {
    return '无返回值';
  }
  
  // 解析返回值为数组（如果适用）
  const parsedReturns = parseArrayData(returns);
  
  if (parsedReturns.length > 1) {
    // 如果是数组形式的返回值
    return (
      <div>
        {parsedReturns.map((ret, index) => {
          const formattedReturn = converter ? converter(ret) : String(ret);
          const isJsonData = isJSON(formattedReturn);
          
          return (
            <div key={index} style={{ marginBottom: '8px' }}>
              {`返回值${index + 1}: `}
              {isJsonData ? (
                <div style={{
                  background: '#f5f5f5',
                  padding: '8px',
                  borderRadius: '4px',
                  margin: '4px 0'
                }}>
                  <CollapsibleJSON data={JSON.parse(formattedReturn)} />
                </div>
              ) : (
                <ContextMenuText text={formattedReturn}>
                  <span>{formattedReturn}</span>
                </ContextMenuText>
              )}
            </div>
          );
        })}
      </div>
    );
  } else {
    // 单个返回值
    const formattedReturn = converter ? converter(parsedReturns[0]) : String(parsedReturns[0]);
    const isJsonData = isJSON(formattedReturn);
    
    return isJsonData ? (
      <div style={{
        background: '#f5f5f5',
        padding: '8px',
        borderRadius: '4px',
        margin: 0
      }}>
        <CollapsibleJSON data={JSON.parse(formattedReturn)} />
      </div>
    ) : (
      <ContextMenuText text={formattedReturn}>
        <span>{formattedReturn}</span>
      </ContextMenuText>
    );
  }
};

const DetailModal = ({ 
  open, 
  record, 
  onCancel,
  width: modalWidth 
}) => {
  // 移除了对 visible 的检查，仅检查 record 的有效性
  if (!record) {
    return null;
  }

  return (
    <Modal
      title="数据详情"
      open={open}
      onCancel={onCancel}
      footer={null}
      width={modalWidth}
      style={{ 
        top: 20
      }}
      bodyStyle={{ 
        padding: 0
      }}
    >
      <Tabs defaultActiveKey="1" tabBarStyle={{ margin: 0 }}>
        <TabPane tab="基本信息" key="1" forceRender>
          <div className="tab-content">
            <Descriptions bordered column={1} size="small">
              <Descriptions.Item label="ID">{record.id}</Descriptions.Item>
              <Descriptions.Item label="时间戳">{record.timestamp}</Descriptions.Item>
              <Descriptions.Item label="方法">
                <div className="data-content">
                  <Tag color="blue">{record.method}</Tag>
                </div>
              </Descriptions.Item>
              <Descriptions.Item label="参数">
                <div className="data-content">
                  {renderArgsList(record.args)}
                </div>
              </Descriptions.Item>
              <Descriptions.Item label="返回值">
                <div className="data-content">
                  {renderReturnValue(record.returns)}
                </div>
              </Descriptions.Item>
            </Descriptions>
          </div>
        </TabPane>
        
        <TabPane tab="十六进制" key="2" forceRender>
          <div className="tab-content">
            <Descriptions bordered column={1} size="small">
              <Descriptions.Item label="方法 (原始)">
                <div className="data-content">
                  <Tag color="blue">{record.method}</Tag>
                </div>
              </Descriptions.Item>
              <Descriptions.Item label="参数 (Hex)">
                <div className="data-content hex-content">
                  {renderArgsList(record.args, convertToHex)}
                </div>
              </Descriptions.Item>
              <Descriptions.Item label="返回值 (Hex)">
                <div className="data-content hex-content">
                  {renderReturnValue(record.returns, convertToHex)}
                </div>
              </Descriptions.Item>
            </Descriptions>
          </div>
        </TabPane>
        
        <TabPane tab="原始数据" key="3" forceRender>
          <div className="tab-content">
            <pre style={{
              whiteSpace: 'pre-wrap',
              wordWrap: 'break-word',
              fontSize: '12px',
              lineHeight: '1.5',
              border: '1px solid #e8e8e8',
              margin: 0
            }}>
              {record ? JSON.stringify(record, null, 2) : '未选择任何记录'}
            </pre>
          </div>
        </TabPane>
      </Tabs>
    </Modal>
  );
};

export default DetailModal;