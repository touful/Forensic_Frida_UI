import React, { useState, useEffect } from 'react';
import { Layout, Card, Form, Input, Button, Select, Collapse, Tag, Modal, List, message } from 'antd';
import { RocketOutlined, PlusOutlined, DeleteOutlined } from '@ant-design/icons';
import DataFilter from '../DataFilter';

const { ipcRenderer } = window.require('electron');
const { Sider } = Layout;
const { Panel } = Collapse;
const { Option } = Select;

const Sidebar = ({ 
  windowSize,
  collapsedSider,
  configFiles,
  selectedConfig,
  setSelectedConfig,
  targetPackage,
  setTargetPackage,
  deviceId,
  setDeviceId,
  startCapture,
  hookConfigs,
  setHookConfigs,
  sendHookConfig,
  form,
  setSearchText,
  onFilterChange
}) => {
  const [modalVisible, setModalVisible] = useState(false);
  const [selectedConfigDetails, setSelectedConfigDetails] = useState(null);
  const [devices, setDevices] = useState([]); // 存储ADB设备列表
  const [loadingDevices, setLoadingDevices] = useState(false); // 设备列表加载状态
  const [useCustomDeviceId, setUseCustomDeviceId] = useState(false); // 是否使用自定义设备ID

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

  // 显示配置详情
  const showConfigDetails = (config) => {
    setSelectedConfigDetails(config);
    setModalVisible(true);
  };

  // 获取ADB设备列表
  const getAdbDevices = async () => {
    setLoadingDevices(true);
    try {
      const result = await ipcRenderer.invoke('get-adb-devices');
      if (result.success) {
        setDevices(result.devices);
        // 如果当前设备ID不在列表中，切换到自定义模式
        if (result.devices.length > 0 && !result.devices.includes(deviceId) && deviceId !== '') {
          setUseCustomDeviceId(true);
        }
      } else {
        message.error('获取设备列表失败: ' + result.error);
      }
    } catch (error) {
      message.error('获取设备列表时发生错误: ' + error.message);
    } finally {
      setLoadingDevices(false);
    }
  };

  // 组件挂载时获取设备列表
  useEffect(() => {
    getAdbDevices();
  }, []);

  // 处理设备选择变化
  const handleDeviceChange = (value) => {
    if (value === 'other') {
      setUseCustomDeviceId(true);
      setDeviceId('');
    } else {
      setUseCustomDeviceId(false);
      setDeviceId(value);
    }
  };

  return (
    <Sider 
      width={windowSize.width < 768 ? 300 : 400} 
      style={{ 
        background: '#f0f2f5', 
        height: 'calc(100vh - 64px)',
        overflow: 'hidden',
        position: 'relative',
        top: 0
      }}
      collapsed={collapsedSider}
      collapsedWidth={0}
    >
      <div style={{ 
        height: '100%',
        overflowY: 'auto',
        padding: '16px',
        boxSizing: 'border-box'
      }}>
        <Card title="目标应用设置" size="small" style={{ marginBottom: 16 }}>
          <Form layout="vertical">
            <Form.Item label="配置文件">
              <Select
                value={selectedConfig}
                onChange={value => setSelectedConfig(value)}
                placeholder="请选择配置文件"
                size={windowSize.width < 576 ? 'small' : 'middle'}
              >
                {configFiles && configFiles.length > 0 ? (
                  configFiles.map(file => (
                    <Select.Option key={file.name} value={file.name}>
                      <div>
                        <div>{file.description}</div>
                        {file.tips && (
                          <div style={{ fontSize: '12px', color: '#999', marginTop: '2px' }}>
                            {file.tips}
                          </div>
                        )}
                      </div>
                    </Select.Option>
                  ))
                ) : (
                  <Select.Option value="loading" disabled>
                    加载中...
                  </Select.Option>
                )}
              </Select>
            </Form.Item>
            
            <Form.Item label="目标应用包名">
              <Input
                value={targetPackage}
                onChange={e => setTargetPackage(e.target.value)}
                placeholder="例如: com.example.app"
                size={windowSize.width < 576 ? 'small' : 'middle'}
              />
            </Form.Item>
            
            <Form.Item label="设备ID">
              <div style={{ display: 'flex', gap: 8 }}>
                <Select
                  value={useCustomDeviceId ? 'other' : deviceId}
                  onChange={handleDeviceChange}
                  placeholder="请选择或输入设备ID"
                  size={windowSize.width < 576 ? 'small' : 'middle'}
                  loading={loadingDevices}
                  style={{ flex: 1 }}
                >
                  {devices.map(device => (
                    <Option key={device} value={device}>{device}</Option>
                  ))}
                  <Option value="other">其他 (自定义)</Option>
                </Select>
                <Button 
                  onClick={getAdbDevices}
                  loading={loadingDevices}
                  size={windowSize.width < 576 ? 'small' : 'middle'}
                >
                  刷新
                </Button>
              </div>
              
              {useCustomDeviceId && (
                <Input
                  value={deviceId}
                  onChange={e => setDeviceId(e.target.value)}
                  placeholder="请输入设备ID"
                  size={windowSize.width < 576 ? 'small' : 'middle'}
                  style={{ marginTop: 8 }}
                />
              )}
            </Form.Item>
          </Form>
        </Card>
        
        <Card title="搜索和过滤" size="small" style={{ marginBottom: 16 }}>
          <Form layout="vertical">
            <Form.Item label="搜索">
              <Input
                placeholder="搜索方法、参数或返回值"
                onChange={e => setSearchText(e.target.value)}
                size={windowSize.width < 576 ? 'small' : 'middle'}
              />
            </Form.Item>
          </Form>
          <DataFilter onFilterChange={onFilterChange} />
        </Card>
        
        <Card title="Hook配置" size="small">
          <Collapse defaultActiveKey={['1']}>
            <Panel header="配置Hook类和方法" key="1">
              <Form form={form} layout="vertical">
                {hookConfigs && hookConfigs.length > 0 ? (
                  hookConfigs.map((config, index) => (
                    <Card 
                      size="small" 
                      key={index} 
                      style={{ marginBottom: 16 }}
                      onClick={() => showConfigDetails(config)}
                      hoverable
                    >
                      <div style={{ display: 'flex', alignItems: 'center' }}>
                        <Tag color="blue" style={{ marginRight: 8 }}>
                          {index + 1}
                        </Tag>
                        <div>
                          <div style={{ fontWeight: 500 }}>
                            {config.class}.{config.method}
                          </div>
                          {(config.avoid_args && config.avoid_args.length > 0) || 
                           (config.avoid_returns && config.avoid_returns.length > 0) ? (
                            <div style={{ fontSize: '12px', color: '#666', marginTop: 4 }}>
                              点击查看详情
                            </div>
                          ) : null}
                        </div>
                      </div>
                    </Card>
                  ))
                ) : (
                  <div style={{ textAlign: 'center', padding: '20px', color: '#999' }}>
                    未找到Hook配置，请选择配置文件
                  </div>
                )}
              </Form>
            </Panel>
          </Collapse>
        </Card>
      </div>

      {/* 配置详情模态框 */}
      <Modal
        title="Hook配置详情"
        visible={modalVisible}
        onCancel={() => setModalVisible(false)}
        footer={null}
        width={500}
      >
        {selectedConfigDetails && (
          <div>
            <List
              size="small"
              bordered
              dataSource={[
                { label: '类名', value: selectedConfigDetails.class },
                { label: '方法名', value: selectedConfigDetails.method }
              ]}
              renderItem={item => (
                <List.Item>
                  <strong>{item.label}:</strong> {item.value}
                </List.Item>
              )}
            />
            
            {selectedConfigDetails.avoid_args && selectedConfigDetails.avoid_args.length > 0 && (
              <div style={{ marginTop: 16 }}>
                <h4>避免参数:</h4>
                <List
                  size="small"
                  bordered
                  dataSource={selectedConfigDetails.avoid_args}
                  renderItem={(item, index) => (
                    <List.Item>
                      <div>
                        <div><strong>规则 {index + 1}:</strong></div>
                        {item.front && item.front.length > 0 && (
                          <div>前缀匹配: {item.front.join(', ')}</div>
                        )}
                        {item.back && item.back.length > 0 && (
                          <div>后缀匹配: {item.back.join(', ')}</div>
                        )}
                        {item.matchall && item.matchall.length > 0 && (
                          <div>完整匹配: {item.matchall.join(', ')}</div>
                        )}
                      </div>
                    </List.Item>
                  )}
                />
              </div>
            )}
            
            {selectedConfigDetails.avoid_returns && selectedConfigDetails.avoid_returns.length > 0 && (
              <div style={{ marginTop: 16 }}>
                <h4>避免返回值:</h4>
                <List
                  size="small"
                  bordered
                  dataSource={selectedConfigDetails.avoid_returns}
                  renderItem={(item, index) => (
                    <List.Item>
                      <div>
                        <div><strong>规则 {index + 1}:</strong></div>
                        {item.front && item.front.length > 0 && (
                          <div>前缀匹配: {item.front.join(', ')}</div>
                        )}
                        {item.back && item.back.length > 0 && (
                          <div>后缀匹配: {item.back.join(', ')}</div>
                        )}
                        {item.matchall && item.matchall.length > 0 && (
                          <div>完整匹配: {item.matchall.join(', ')}</div>
                        )}
                      </div>
                    </List.Item>
                  )}
                />
              </div>
            )}
          </div>
        )}
      </Modal>
    </Sider>
  );
};

export default Sidebar;