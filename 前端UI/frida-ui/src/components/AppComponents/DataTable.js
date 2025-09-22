import React, { useState, useEffect, useRef, useMemo } from 'react';
import { Layout, Table, Input, Row, Col, Card, Typography, Tooltip } from 'antd';
import { SearchOutlined, CaretUpOutlined, CaretDownOutlined } from '@ant-design/icons';
import ResizableTitle from './DataTable/components/ResizableTitle';
import DetailModal from './DataTable/components/DetailModal';
import { getDefaultColumns } from './DataTable/columns';
import PermissionAnalysis from './PermissionAnalysis';
import SmartForensics from './SmartForensics';

const { Content } = Layout;
const { Text } = Typography;

const DEFAULT_COLUMNS = [
  {
    title: '时间戳',
    dataIndex: 'timestamp',
    key: 'timestamp',
    width: 150,
  },
  {
    title: '方法',
    dataIndex: 'method',
    key: 'method',
    width: 200,
  },
  {
    title: '参数',
    dataIndex: 'args',
    key: 'args',
    width: 250,
  },
  {
    title: '返回值',
    dataIndex: 'returns',
    key: 'returns',
    width: 250,
  }
];

const DataTable = ({ 
  windowSize, 
  data, 
  filteredData,
  isCapturing,
  searchText,
  setSearchText,
  columns: propsColumns, // 重命名属性
  pageType // 新增页面类型参数
}) => {
  const containerRef = useRef(null);
  const [columns, setColumns] = useState([]); // 初始为空，等待 defaultColumns 计算
  const [containerWidth, setContainerWidth] = useState(0); // 添加containerWidth状态
  const [sortedData, setSortedData] = useState([]); // 存储排序后的数据
  const [sortConfig, setSortConfig] = useState({ key: 'id', direction: 'asc' }); // 排序配置，默认按ID升序
  const [pagination, setPagination] = useState({
    current: 1,
    pageSize: 200,
    pageSizeOptions: ['50', '200', '500', '1000'],
    showSizeChanger: true,
    showQuickJumper: true,
    showTotal: (total, range) => `${range[0]}-${range[1]} 条，共 ${total} 条`
  });
  
  // 详细信息模态框相关状态
  const [detailModalVisible, setDetailModalVisible] = useState(false);
  const [selectedRecord, setSelectedRecord] = useState(null);
  const [modalWidth, setModalWidth] = useState(800);

  const defaultColumns = useMemo(() => {
    // 确保windowSize存在再调用getDefaultColumns
    return windowSize ? getDefaultColumns(windowSize) : [];
  }, [windowSize]);

  // 根据页面类型渲染不同内容
  const renderContent = () => {
    switch (pageType) {
      case 'permission-analysis':
        return <PermissionAnalysis windowSize={windowSize} />;
      
      case 'smart-forensics':
        return <SmartForensics windowSize={windowSize} />;
        
      case 'frida-monitor':
      default:
        return renderFridaMonitor();
    }
  };


  // 处理排序
  const handleSort = (key) => {
    let direction = 'asc';
    if (sortConfig.key === key && sortConfig.direction === 'asc') {
      direction = 'desc';
    }
    setSortConfig({ key, direction });
  };

  // 根据排序配置对数据进行排序
  const sortData = (dataToSort = [], config) => {
    // 确保 dataToSort 是数组
    if (!Array.isArray(dataToSort)) {
      return [];
    }
    
    if (!config.key) return dataToSort;

    return [...dataToSort].sort((a, b) => {
      let aValue = a[config.key];
      let bValue = b[config.key];

      // 特殊处理args字段，将其转换为字符串进行比较
      if (config.key === 'args') {
        aValue = Array.isArray(aValue) ? aValue.map(arg => String(arg)).join(', ') : String(aValue);
        bValue = Array.isArray(bValue) ? bValue.map(arg => String(arg)).join(', ') : String(bValue);
      }

      // 处理数字类型
      if (typeof aValue === 'number' && typeof bValue === 'number') {
        if (config.direction === 'asc') {
          return aValue - bValue;
        } else {
          return bValue - aValue;
        }
      }

      // 处理字符串类型
      aValue = String(aValue);
      bValue = String(bValue);

      if (config.direction === 'asc') {
        return aValue.localeCompare(bValue);
      } else {
        return bValue.localeCompare(aValue);
      }
    });
  };

  // 当过滤数据或排序配置改变时，更新排序后的数据
  useEffect(() => {
    const sorted = sortData(filteredData, sortConfig);
    setSortedData(sorted);
  }, [filteredData, sortConfig]);

  useEffect(() => {
    const updateContainerWidth = () => {
      if (containerRef.current) {
        setContainerWidth(containerRef.current.offsetWidth);
      }
    };

    // 初始化容器宽度
    updateContainerWidth();

    const resizeObserver = new ResizeObserver(updateContainerWidth);

    if (containerRef.current) {
      resizeObserver.observe(containerRef.current);
    }

    return () => {
      resizeObserver.disconnect();
    };
  }, []);

  const handleResize = (index) => (e, { size }) => {
    const newColumns = [...tableColumns];
    newColumns[index] = {
      ...newColumns[index],
      width: size.width,
    };
    setTableColumns(newColumns);
  };

  // 初始化列配置：优先使用父组件传入的列，否则使用根据窗口大小动态生成的默认列
  useEffect(() => {
    if (propsColumns && Array.isArray(propsColumns) && propsColumns.length > 0) {
      setColumns(propsColumns);
    } else if (defaultColumns && defaultColumns.length > 0) {
      setColumns(defaultColumns);
    }
  }, [propsColumns, defaultColumns]);

  // 计算有效的表格列，过滤掉undefined元素并添加排序和调整大小功能
  const tableColumns = useMemo(() => {
    // 确保columns存在且为数组
    if (!columns || !Array.isArray(columns)) return [];
    
    // 过滤掉undefined或null的列
    const validColumns = columns.filter(col => col !== undefined && col !== null);
    
    return validColumns.map(col => ({
      ...col,
      title: (
        <Tooltip title={`点击排序`}>
          <span 
            onClick={() => handleSort(col.dataIndex)}
            style={{ 
              cursor: 'pointer',
              display: 'inline-flex',
              alignItems: 'center'
            }}
          >
            {col.title}
            {sortConfig.key === col.dataIndex && (
              sortConfig.direction === 'asc' ? 
              <CaretUpOutlined style={{ fontSize: '12px', marginLeft: '4px' }} /> : 
              <CaretDownOutlined style={{ fontSize: '12px', marginLeft: '4px' }} />
            )}
          </span>
        </Tooltip>
      ),
      onHeaderCell: (column) => ({
        width: column.width,
        onResize: handleResize(validColumns.indexOf(column)),
      }),
    }));
  }, [columns, sortConfig]);

  // 计算总宽度
  const totalWidth = useMemo(() => {
    // 确保tableColumns存在
    if (!tableColumns) return 0;
    
    return tableColumns.reduce((sum, col) => sum + (col.width || 200), 0);
  }, [tableColumns]);

  // 处理分页变化
  const handleTableChange = (paginationObj) => {
    setPagination({
      ...pagination,
      current: paginationObj.current,
      pageSize: paginationObj.pageSize,
    });
  };

  // 处理行点击事件
  const handleRowClick = (record) => {
    setSelectedRecord(record);
    setDetailModalVisible(true);
    
    // 根据窗口大小动态调整模态框宽度
    const width = window.innerWidth < 768 ? window.innerWidth * 0.95 : Math.min(1200, window.innerWidth * 0.8);
    setModalWidth(width);
  };

  // 关闭详细信息模态框
  const closeDetailModal = () => {
    setDetailModalVisible(false);
    setSelectedRecord(null);
  };

  // 渲染Frida监控内容
  const renderFridaMonitor = () => {
    // 由于我们已经确保了columns始终有默认值，这里可以直接渲染
    
    const components = {
      header: {
        cell: ResizableTitle,
      },
    };

    // 添加样式到head部分
    const tableHeaderStyle = `
      .react-resizable {
        position: relative;
        background-clip: padding-box;
      }
      
      .react-resizable-handle {
        position: absolute;
        right: -5px;
        bottom: 0;
        top: 0;
        width: 10px;
        cursor: col-resize;
        z-index: 1;
      }
      
      .react-resizable-handle:hover {
        border-right: 2px solid #1890ff;
      }
      
      .ant-table-thead > tr > th {
        position: relative;
        background: #fafafa;
        font-weight: 500;
      }
      
      .ant-table-tbody > tr > td {
        word-break: break-all;
        word-wrap: break-word;
      }
    `;

    return (
      <>
        <style>{tableHeaderStyle}</style>
        <Row gutter={windowSize && windowSize.width < 576 ? 8 : 16} style={{ marginBottom: 16 }}>
          <Col>
            <Card size="small">
              <div style={{ 
                fontSize: windowSize && windowSize.width < 576 ? '12px' : '14px', 
                fontWeight: 500 
              }}>
                状态: {isCapturing ? '捕获中...' : '已停止'}
              </div>
            </Card>
          </Col>
          <Col>
            <Card size="small">
              <div style={{ 
                fontSize: windowSize && windowSize.width < 576 ? '12px' : '14px', 
                fontWeight: 500 
              }}>
                数据条数: {data?.length || 0}
              </div>
            </Card>
          </Col>
          <Col flex="auto">
            <Input
              placeholder="搜索方法、参数或返回值..."
              prefix={<SearchOutlined />}
              value={searchText}
              onChange={(e) => setSearchText(e.target.value)}
              allowClear
              size={windowSize && windowSize.width < 576 ? "small" : "default"}
            />
          </Col>
        </Row>
        
        <Table
          columns={tableColumns}
          dataSource={sortedData}
          pagination={{ 
            ...pagination,
            size: windowSize && windowSize.width < 576 ? 'small' : 'default'
          }}
          scroll={{ 
            y: windowSize && windowSize.width < 576 
              ? 'calc(100vh - 340px)' 
              : windowSize && windowSize.height < 768 
                ? 'calc(100vh - 320px)' 
                : 'calc(100vh - 310px)' 
          }}
          size={windowSize && windowSize.width < 576 ? "small" : "middle"}
          components={components}
          tableLayout="fixed"
          sticky
          onChange={handleTableChange}
          onRow={(record) => ({
            onClick: () => handleRowClick(record),
          })}
        />
        
        <DetailModal
          visible={detailModalVisible}
          onCancel={closeDetailModal}
          record={selectedRecord}
          width={modalWidth}
        />
      </>
    );
  };

  return (
    <Content 
      ref={containerRef}
      style={{ 
        padding: windowSize && windowSize.width < 768 ? 12 : 24, 
        background: '#fff',
        height: '100%',
        overflow: 'auto'
      }}
    >
      {renderContent()}
    </Content>
  );
};

export default DataTable;