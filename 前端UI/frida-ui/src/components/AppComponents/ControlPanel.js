import React from 'react';
import { Card, Form, Input, Button } from 'antd';
import { PlusOutlined, DeleteOutlined } from '@ant-design/icons';

const ControlPanel = ({ 
  windowSize,
  hookConfigs,
  setHookConfigs,
  sendHookConfig,
  form
}) => {
  // 添加新的hook配置
  const addHookConfig = () => {
    const newConfig = {
      class: "",
      method: "",
      avoid_args: [],
      avoid_returns: []
    };
    setHookConfigs([...hookConfigs, newConfig]);
  };

  // 删除hook配置
  const removeHookConfig = (index) => {
    const newConfigs = [...hookConfigs];
    newConfigs.splice(index, 1);
    setHookConfigs(newConfigs);
  };

  // 更新hook配置
  const updateHookConfig = (index, field, value) => {
    const newConfigs = [...hookConfigs];
    newConfigs[index][field] = value;
    setHookConfigs(newConfigs);
  };

  return (
    <Card title="Hook配置" size="small">
      <Form form={form} layout="vertical">
        {hookConfigs.map((config, index) => (
          <Card 
            size="small" 
            key={index} 
            style={{ marginBottom: 16 }}
            title={`Hook配置 ${index + 1}`}
            extra={
              <Button 
                icon={<DeleteOutlined />} 
                onClick={() => removeHookConfig(index)}
                danger
                size="small"
              />
            }
          >
            <Form.Item label="类名">
              <Input
                value={config.class}
                onChange={e => updateHookConfig(index, 'class', e.target.value)}
                placeholder="例如: java.lang.String"
                size={windowSize.width < 576 ? 'small' : 'middle'}
              />
            </Form.Item>
            
            <Form.Item label="方法名">
              <Input
                value={config.method}
                onChange={e => updateHookConfig(index, 'method', e.target.value)}
                placeholder="例如: equals"
                size={windowSize.width < 576 ? 'small' : 'middle'}
              />
            </Form.Item>
            
            <Form.Item label="避免的参数 (JSON格式)">
              <Input.TextArea
                value={JSON.stringify(config.avoid_args)}
                onChange={e => {
                  try {
                    const parsed = JSON.parse(e.target.value);
                    updateHookConfig(index, 'avoid_args', parsed);
                  } catch (err) {
                    // 如果JSON格式不正确，不更新
                  }
                }}
                placeholder='[{"front": ["prefix"], "back": ["suffix"], "matchall": ["exact"]}]'
                autoSize={{ minRows: 2, maxRows: 4 }}
                size={windowSize.width < 576 ? 'small' : 'middle'}
              />
            </Form.Item>
            
            <Form.Item label="避免的返回值 (JSON格式)">
              <Input.TextArea
                value={JSON.stringify(config.avoid_returns)}
                onChange={e => {
                  try {
                    const parsed = JSON.parse(e.target.value);
                    updateHookConfig(index, 'avoid_returns', parsed);
                  } catch (err) {
                    // 如果JSON格式不正确，不更新
                  }
                }}
                placeholder='[{"front": ["prefix"], "back": ["suffix"], "matchall": ["exact"]}]'
                autoSize={{ minRows: 2, maxRows: 4 }}
                size={windowSize.width < 576 ? 'small' : 'middle'}
              />
            </Form.Item>
          </Card>
        ))}
        
        <Form.Item>
          <Button 
            type="dashed" 
            onClick={addHookConfig} 
            block 
            icon={<PlusOutlined />}
            size={windowSize.width < 576 ? 'small' : 'middle'}
          >
            添加Hook配置
          </Button>
        </Form.Item>
        
        <Form.Item>
          <Button 
            type="primary" 
            onClick={sendHookConfig} 
            block
            size={windowSize.width < 576 ? 'small' : 'middle'}
          >
            应用Hook配置
          </Button>
        </Form.Item>
      </Form>
    </Card>
  );
};

export default ControlPanel;