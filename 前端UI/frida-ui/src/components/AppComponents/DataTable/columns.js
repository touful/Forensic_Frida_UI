import React from 'react';
import { Tag } from 'antd';

export const getDefaultColumns = (windowSize) => [
  {
    title: 'ID',
    dataIndex: 'id',
    width: 80,
    fixed: windowSize.width < 768 ? false : 'left'
  },
  {
    title: '时间戳',
    dataIndex: 'timestamp',
    width: windowSize.width < 576 ? 80 : 120,
    ellipsis: true
  },
  {
    title: '方法',
    dataIndex: 'method',
    className: 'method-column',
    width: windowSize.width < 576 ? 150 : 250,
    ellipsis: true,
    render: (text) => <Tag color="blue">{text}</Tag>
  },
  {
    title: '参数',
    dataIndex: 'args',
    className: 'args-column',
    width: windowSize.width < 576 ? 150 : 200,
    ellipsis: true,
    render: (args) => (
      <div>
        {args && args.length > 0 ? (
          args.map((arg, index) => (
            <div key={index} style={{ 
              maxWidth: 300, 
              overflow: 'hidden', 
              textOverflow: 'ellipsis',
              whiteSpace: 'nowrap'
            }}>
              {String(arg)}
            </div>
          ))
        ) : (
          <span>无参数</span>
        )}
      </div>
    )
  },
  {
    title: '返回值',
    dataIndex: 'returns',
    className: 'returns-column',
    width: windowSize.width < 576 ? 150 : 200,
    ellipsis: true
  }
];