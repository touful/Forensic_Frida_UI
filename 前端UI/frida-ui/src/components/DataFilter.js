import React, { useState, useContext } from 'react';
import { Form, Input, Select, Button, Collapse, DatePicker } from 'antd';

const { Panel } = Collapse;
const { RangePicker } = DatePicker;

// 创建Context用于在组件间传递过滤条件
export const FilterContext = React.createContext();

const DataFilter = ({ onFilterChange }) => {
  const [form] = Form.useForm();
  
  const handleFinish = (values) => {
    console.log('过滤条件:', values);
    // 将过滤条件传递给父组件
    if (onFilterChange) {
      onFilterChange(values);
    }
  };

  const handleReset = () => {
    form.resetFields();
    // 重置时也通知父组件
    if (onFilterChange) {
      onFilterChange({});
    }
  };

  return (
    <Form
      form={form}
      layout="vertical"
      onFinish={handleFinish}
    >
      <Collapse defaultActiveKey={['1']} size="small">
        <Panel header="基础过滤" key="1">
          <Form.Item name="method" label="方法名">
            <Input placeholder="输入方法名" />
          </Form.Item>
          
          <Form.Item name="args" label="参数包含">
            <Input placeholder="参数包含的内容" />
          </Form.Item>
          
          <Form.Item name="returns" label="返回值">
            <Input placeholder="返回值包含的内容" />
          </Form.Item>
        </Panel>
        
        <Panel header="高级过滤" key="2">
          <Form.Item name="timeRange" label="时间范围">
            <RangePicker showTime format="YYYY-MM-DD HH:mm:ss" />
          </Form.Item>
        </Panel>
      </Collapse>
      
      <Form.Item style={{ marginTop: 16 }}>
        <Button type="primary" htmlType="submit" block>
          应用过滤
        </Button>
        <Button onClick={handleReset} block style={{ marginTop: 8 }}>
          重置条件
        </Button>
      </Form.Item>
    </Form>
  );
};

export default DataFilter;