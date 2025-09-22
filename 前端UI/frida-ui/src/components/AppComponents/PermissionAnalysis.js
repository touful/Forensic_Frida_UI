import React, { useState, useEffect } from 'react';
import { Card, Table, Button, Space, Tag, Typography, Row, Col, Statistic, Progress } from 'antd';
import { ReloadOutlined, DownloadOutlined } from '@ant-design/icons';

const { Title, Text } = Typography;

const PermissionAnalysis = ({ windowSize }) => {
  const [permissions, setPermissions] = useState([]);
  const [loading, setLoading] = useState(false);
  const [analysisStats, setAnalysisStats] = useState({
    total: 0,
    dangerous: 0,
    normal: 0,
    signature: 0
  });

  // 模拟权限数据
  const generateMockPermissions = () => {
    const permissionTypes = ['DANGEROUS', 'NORMAL', 'SIGNATURE', 'RESTRICTED'];
    const permissionsList = [
      'android.permission.INTERNET',
      'android.permission.ACCESS_FINE_LOCATION',
      'android.permission.CAMERA',
      'android.permission.READ_CONTACTS',
      'android.permission.WRITE_EXTERNAL_STORAGE',
      'android.permission.RECORD_AUDIO',
      'android.permission.READ_SMS',
      'android.permission.CALL_PHONE',
      'android.permission.ACCESS_COARSE_LOCATION',
      'android.permission.READ_PHONE_STATE',
      'android.permission.SEND_SMS',
      'android.permission.RECEIVE_BOOT_COMPLETED'
    ];

    return permissionsList.map((perm, index) => ({
      key: index,
      name: perm,
      type: permissionTypes[Math.floor(Math.random() * permissionTypes.length)],
      used: Math.random() > 0.3, // 70%概率显示为已使用
      description: `这是 ${perm} 权限的描述信息，用于控制应用对特定功能的访问。`
    }));
  };

  // 加载权限数据
  const loadPermissions = () => {
    setLoading(true);
    // 模拟API调用延迟
    setTimeout(() => {
      const mockData = generateMockPermissions();
      setPermissions(mockData);
      
      // 计算统计信息
      const total = mockData.length;
      const dangerous = mockData.filter(p => p.type === 'DANGEROUS').length;
      const normal = mockData.filter(p => p.type === 'NORMAL').length;
      const signature = mockData.filter(p => p.type === 'SIGNATURE').length;
      
      setAnalysisStats({
        total,
        dangerous,
        normal,
        signature
      });
      
      setLoading(false);
    }, 800);
  };

  // 组件挂载时加载数据
  useEffect(() => {
    loadPermissions();
  }, []);

  // 权限类型标签颜色
  const getPermissionTypeColor = (type) => {
    switch (type) {
      case 'DANGEROUS': return 'red';
      case 'NORMAL': return 'green';
      case 'SIGNATURE': return 'blue';
      case 'RESTRICTED': return 'orange';
      default: return 'default';
    }
  };

  // 表格列定义
  const columns = [
    {
      title: '权限名称',
      dataIndex: 'name',
      key: 'name',
      render: (text) => (
        <Text code copyable>{text}</Text>
      )
    },
    {
      title: '类型',
      dataIndex: 'type',
      key: 'type',
      render: (text) => (
        <Tag color={getPermissionTypeColor(text)}>{text}</Tag>
      ),
      filters: [
        { text: 'DANGEROUS', value: 'DANGEROUS' },
        { text: 'NORMAL', value: 'NORMAL' },
        { text: 'SIGNATURE', value: 'SIGNATURE' },
        { text: 'RESTRICTED', value: 'RESTRICTED' }
      ],
      onFilter: (value, record) => record.type === value
    },
    {
      title: '使用状态',
      dataIndex: 'used',
      key: 'used',
      render: (used) => (
        <Tag color={used ? 'green' : 'default'}>
          {used ? '已使用' : '未使用'}
        </Tag>
      ),
      filters: [
        { text: '已使用', value: true },
        { text: '未使用', value: false }
      ],
      onFilter: (value, record) => record.used === value
    },
    {
      title: '描述',
      dataIndex: 'description',
      key: 'description',
      ellipsis: true
    }
  ];

  return (
    <div style={{ padding: windowSize.width < 576 ? '12px' : '24px' }}>
      <Title level={4}>权限分析</Title>
      <Text type="secondary">分析应用请求的权限及其使用情况</Text>
      
      {/* 统计信息卡片 */}
      <Row gutter={[16, 16]} style={{ marginTop: 16 }}>
        <Col xs={12} sm={6}>
          <Card>
            <Statistic title="总权限数" value={analysisStats.total} />
          </Card>
        </Col>
        <Col xs={12} sm={6}>
          <Card>
            <Statistic title="危险权限" value={analysisStats.dangerous} valueStyle={{ color: '#cf1322' }} />
          </Card>
        </Col>
        <Col xs={12} sm={6}>
          <Card>
            <Statistic title="普通权限" value={analysisStats.normal} valueStyle={{ color: '#3f8600' }} />
          </Card>
        </Col>
        <Col xs={12} sm={6}>
          <Card>
            <Statistic title="签名权限" value={analysisStats.signature} />
          </Card>
        </Col>
      </Row>
      
      {/* 危险权限占比进度条 */}
      <Card style={{ marginTop: 16 }}>
        <Text strong>危险权限占比</Text>
        <Progress 
          percent={analysisStats.total ? Math.round((analysisStats.dangerous / analysisStats.total) * 100) : 0} 
          status="exception" 
          style={{ marginTop: 8 }}
        />
      </Card>
      
      {/* 操作按钮 */}
      <Space style={{ marginTop: 16 }}>
        <Button 
          icon={<ReloadOutlined />} 
          onClick={loadPermissions} 
          loading={loading}
        >
          刷新数据
        </Button>
        <Button icon={<DownloadOutlined />}>导出报告</Button>
      </Space>
      
      {/* 权限表格 */}
      <Card style={{ marginTop: 16 }}>
        <Table
          dataSource={permissions}
          columns={columns}
          loading={loading}
          pagination={{
            pageSize: windowSize.width < 576 ? 5 : 10
          }}
          scroll={{ x: windowSize.width < 576 ? 600 : 'max-content' }}
          size={windowSize.width < 576 ? "small" : "default"}
        />
      </Card>
    </div>
  );
};

export default PermissionAnalysis;