import React, { useState, memo } from 'react';
import { CaretRightOutlined, CaretDownOutlined } from '@ant-design/icons';
import { Dropdown, Menu, message } from 'antd';

// 使用memo优化ContextMenuText组件
const ContextMenuText = memo(({ children, text }) => {
  const handleCopy = () => {
    navigator.clipboard.writeText(text);
    message.success('已复制到剪贴板');
  };

  const handleSmartDecode = () => {
    // TODO: 实现智能解码功能
    message.info('智能解码功能待实现');
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
      <span style={{ display: 'inline-block' }}>
        {children}
      </span>
    </Dropdown>
  );
});

// 使用memo优化CollapsibleJSON组件
const CollapsibleJSON = memo(({ data, indentLevel = 0 }) => {
  // 默认只展开根节点，不展开内部的对象或数组
  const getDefaultExpandedKeys = (obj, parentKey = '') => {
    const keys = {};
    // 展开根节点（第一层）
    if (parentKey === '') {
      keys['root'] = true;
    }
    
    // 不再默认展开任何嵌套的对象或数组
    // 所有嵌套的对象和数组默认都是收起状态
    return keys;
  };

  const [expandedKeys, setExpandedKeys] = useState(() => getDefaultExpandedKeys(data));

  // Toggle the expansion state of a key
  const toggleKey = (keyPath) => {
    setExpandedKeys(prev => ({
      ...prev,
      [keyPath]: !prev[keyPath]
    }));
  };

  // Render a value, either as a primitive or as a collapsible object/array
  const renderValue = (value, keyPath) => {
    // Handle null and undefined
    if (value === null) {
      return <span style={{ color: '#888' }}>null</span>;
    }
    
    if (value === undefined) {
      return <span style={{ color: '#888' }}>undefined</span>;
    }

    // Handle primitive types
    if (typeof value !== 'object') {
      if (typeof value === 'string') {
        return (
          <ContextMenuText text={value}>
            <span style={{ color: '#d14' }}>"{value}"</span>
          </ContextMenuText>
        );
      }
      if (typeof value === 'number') {
        return (
          <ContextMenuText text={String(value)}>
            <span style={{ color: '#164' }}>{value}</span>
          </ContextMenuText>
        );
      }
      if (typeof value === 'boolean') {
        return (
          <ContextMenuText text={value.toString()}>
            <span style={{ color: '#164' }}>{value.toString()}</span>
          </ContextMenuText>
        );
      }
      return (
        <ContextMenuText text={value.toString()}>
          <span>{value.toString()}</span>
        </ContextMenuText>
      );
    }

    // Handle arrays
    if (Array.isArray(value)) {
      return (
        <CollapsibleArray 
          data={value} 
          keyPath={keyPath} 
          expanded={expandedKeys[keyPath]} 
          onToggle={() => toggleKey(keyPath)}
          indentLevel={indentLevel + 1}
          expandedKeys={expandedKeys}
          toggleKey={toggleKey}
        />
      );
    }

    // Handle objects
    return (
      <CollapsibleObject 
        data={value} 
        keyPath={keyPath} 
        expanded={expandedKeys[keyPath]} 
        onToggle={() => toggleKey(keyPath)}
        indentLevel={indentLevel + 1}
        expandedKeys={expandedKeys}
        toggleKey={toggleKey}
      />
    );
  };

  return (
    <div style={{ 
      fontFamily: 'monospace', 
      fontSize: '12px', 
      lineHeight: '1.2'
    }}>
      {renderValue(data, 'root')}
    </div>
  );
});

// 使用memo优化CollapsibleObject组件
const CollapsibleObject = memo(({ data, keyPath, expanded, onToggle, indentLevel, expandedKeys, toggleKey }) => {
  const indent = indentLevel * 1; // 一致的缩进单位
  
  if (Object.keys(data).length === 0) {
    return <span>{'{}'}</span>;
  }

  // Helper function to render primitive values
  const renderPrimitiveValue = (value) => {
    if (value === null) {
      return <span style={{ color: '#888' }}>null</span>;
    }
    
    if (value === undefined) {
      return <span style={{ color: '#888' }}>undefined</span>;
    }
    
    if (typeof value === 'string') {
      return (
        <ContextMenuText text={value}>
          <span style={{ color: '#d14' }}>"{value}"</span>
        </ContextMenuText>
      );
    }
    
    if (typeof value === 'number') {
      return (
        <ContextMenuText text={String(value)}>
          <span style={{ color: '#164' }}>{value}</span>
        </ContextMenuText>
      );
    }
    
    if (typeof value === 'boolean') {
      return (
        <ContextMenuText text={value.toString()}>
          <span style={{ color: '#164' }}>{value.toString()}</span>
        </ContextMenuText>
      );
    }
    
    return (
      <ContextMenuText text={value.toString()}>
        <span>{value.toString()}</span>
      </ContextMenuText>
    );
  };

  return (
    <div>
      <div 
        onClick={onToggle}
        style={{ cursor: 'pointer', display: 'inline-flex', alignItems: 'center', lineHeight: '1.2' }}
      >
        {expanded ? <CaretDownOutlined /> : <CaretRightOutlined />}
        <span style={{ color: '#888', marginLeft: '4px' }}>{'{'}</span>
        {!expanded && (
          <span style={{ color: '#888', fontSize: '0.9em' }}>{Object.keys(data).length}</span>
        )}
        {!expanded && (
          <span style={{ color: '#888' }}>{'}'}</span>
        )}
      </div>
      
      {expanded && (
        <div style={{ marginLeft: indent }}>
          {Object.entries(data).map(([key, value], index, array) => (
            <div key={key} style={{ display: 'flex', lineHeight: '1.2' }}>
              <span style={{ color: '#690', flexShrink: 0 }}>
                <ContextMenuText text={key}>
                  <span>"{key}"</span>
                </ContextMenuText>
              </span>
              <span style={{ color: '#888', margin: '0 4px', flexShrink: 0 }}>:</span>
              <span style={{ flex: 1 }}>
                {// 对于对象中的每个值，我们检查它是否为对象或数组，如果是，则创建可折叠组件
                typeof value === 'object' && value !== null ? (
                  Array.isArray(value) ? (
                    <CollapsibleArray
                      data={value}
                      keyPath={`${keyPath}.${key}`}
                      expanded={!!expandedKeys[`${keyPath}.${key}`]}
                      onToggle={() => toggleKey(`${keyPath}.${key}`)}
                      indentLevel={indentLevel + 1}
                      expandedKeys={expandedKeys}
                      toggleKey={toggleKey}
                    />
                  ) : (
                    <CollapsibleObject
                      data={value}
                      keyPath={`${keyPath}.${key}`}
                      expanded={!!expandedKeys[`${keyPath}.${key}`]}
                      onToggle={() => toggleKey(`${keyPath}.${key}`)}
                      indentLevel={indentLevel + 1}
                      expandedKeys={expandedKeys}
                      toggleKey={toggleKey}
                    />
                  )
                ) : (
                  // 直接渲染基本类型值
                  renderPrimitiveValue(value)
                )}
              </span>
              {index < array.length - 1 && <span style={{ color: '#888' }}>,</span>}
            </div>
          ))}
        </div>
      )}
      
      {expanded && (
        <div style={{ marginLeft: indent, lineHeight: '1.2' }}>
          <span style={{ color: '#888' }}>{'}'}</span>
        </div>
      )}
    </div>
  );
});

// 使用memo优化CollapsibleArray组件
const CollapsibleArray = memo(({ data, keyPath, expanded, onToggle, indentLevel, expandedKeys, toggleKey }) => {
  const indent = indentLevel * 1; // 一致的缩进单位
  
  if (data.length === 0) {
    return <span>{'[]'}</span>;
  }

  // Helper function to render primitive values
  const renderPrimitiveValue = (value) => {
    if (value === null) {
      return <span style={{ color: '#888' }}>null</span>;
    }
    
    if (value === undefined) {
      return <span style={{ color: '#888' }}>undefined</span>
    }
    
    if (typeof value === 'string') {
      return (
        <ContextMenuText text={value}>
          <span style={{ color: '#d14' }}>"{value}"</span>
        </ContextMenuText>
      );
    }
    
    if (typeof value === 'number') {
      return (
        <ContextMenuText text={String(value)}>
          <span style={{ color: '#164' }}>{value}</span>
        </ContextMenuText>
      );
    }
    
    if (typeof value === 'boolean') {
      return (
        <ContextMenuText text={value.toString()}>
          <span style={{ color: '#164' }}>{value.toString()}</span>
        </ContextMenuText>
      );
    }
    
    return (
      <ContextMenuText text={value.toString()}>
        <span>{value.toString()}</span>
      </ContextMenuText>
    );
  };

  return (
    <div>
      <div 
        onClick={onToggle}
        style={{ cursor: 'pointer', display: 'inline-flex', alignItems: 'center', lineHeight: '1.2' }}
      >
        {expanded ? <CaretDownOutlined /> : <CaretRightOutlined />}
        <span style={{ color: '#888', marginLeft: '4px' }}>{'['}</span>
        {!expanded && (
          <span style={{ color: '#888', fontSize: '0.9em' }}>{data.length}</span>
        )}
        {!expanded && (
          <span style={{ color: '#888' }}>{']'}</span>
        )}
      </div>
      
      {expanded && (
        <div style={{ marginLeft: indent }}>
          {data.map((item, index, array) => (
            <div key={index} style={{ display: 'flex', lineHeight: '1.2' }}>
              <span style={{ flex: 1 }}>
                {// 对于数组中的每个项，我们检查它是否为对象或数组，如果是，则创建可折叠组件
                typeof item === 'object' && item !== null ? (
                  Array.isArray(item) ? (
                    <CollapsibleArray
                      data={item}
                      keyPath={`${keyPath}.${index}`}
                      expanded={!!expandedKeys[`${keyPath}.${index}`]}
                      onToggle={() => toggleKey(`${keyPath}.${index}`)}
                      indentLevel={indentLevel + 1}
                      expandedKeys={expandedKeys}
                      toggleKey={toggleKey}
                    />
                  ) : (
                    <CollapsibleObject
                      data={item}
                      keyPath={`${keyPath}.${index}`}
                      expanded={!!expandedKeys[`${keyPath}.${index}`]}
                      onToggle={() => toggleKey(`${keyPath}.${index}`)}
                      indentLevel={indentLevel + 1}
                      expandedKeys={expandedKeys}
                      toggleKey={toggleKey}
                    />
                  )
                ) : (
                  // 直接渲染基本类型值
                  renderPrimitiveValue(item)
                )}
              </span>
              {index < array.length - 1 && <span style={{ color: '#888' }}>,</span>}
            </div>
          ))}
        </div>
      )}
      
      {expanded && (
        <div style={{ marginLeft: indent, lineHeight: '1.2' }}>
          <span style={{ color: '#888' }}>{']'}</span>
        </div>
      )}
    </div>
  );
});

export default CollapsibleJSON;