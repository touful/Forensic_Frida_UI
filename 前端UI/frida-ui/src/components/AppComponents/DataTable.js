import React, { useState, useEffect, useRef, useMemo } from 'react';
import { Layout, Table, Input, Row, Col, Card, Typography, Tooltip } from 'antd';
import { SearchOutlined, CaretUpOutlined, CaretDownOutlined } from '@ant-design/icons';
import ResizableTitle from './DataTable/components/ResizableTitle';
import DetailModal from './DataTable/components/DetailModal';
import { getDefaultColumns } from './DataTable/columns';

const { Content } = Layout;
const { Text } = Typography;

const DataTable = ({ 
  windowSize, 
  data, 
  filteredData, 
  isCapturing,
  searchText,
  setSearchText,
  columns // 接收columns参数
}) => {
  const containerRef = useRef(null);
  const [tableColumns, setTableColumns] = useState([]);
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

  const defaultColumns = getDefaultColumns(windowSize);

  const initColumns = () => {
    return columns.map((col, index) => {
      // 根据屏幕宽度设置默认列宽
      let defaultWidth = 200;
      if (windowSize.width < 576) {
        defaultWidth = 150;
      } else if (windowSize.width < 768) {
        defaultWidth = 180;
      }
      
      // 确保每列都有宽度，默认为计算后的默认宽度
      const width = col.width || defaultWidth;
      return {
        ...col,
        width: width,
        onHeaderCell: (column) => ({
          width: column.width,
          onResize: handleResize(index),
        }),
      };
    });
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
  const sortData = (dataToSort, config) => {
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

  // 设置表格列，添加排序功能
  useEffect(() => {
    const cols = (columns || defaultColumns).map(col => {
      // 为每个列添加排序功能
      return {
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
        )
      };
    });
    setTableColumns(cols);
  }, [columns, sortConfig]);

  // 计算总宽度
  const totalWidth = useMemo(() => {
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
    setModalWidth(800);
  };

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
      background-clip: padding-box;
      width: 100%;
      display: inline-block;
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
    
    /* 强制覆盖Ant Design表格样式 */
    .ant-table {
      width: 100% !important;
      table-layout: fixed !important;
    }
    
    .ant-table-container {
      width: 100% !important;
      display: table !important;
    }
    
    .ant-table-thead > tr {
      display: table-row !important;
      width: 100% !important;
    }
    
    .ant-table-thead > tr > th {
      display: table-cell !important;
      position: static !important;
      float: none !important;
      background: #fafafa !important;
      font-weight: 500 !important;
      overflow: hidden !important;
      text-overflow: ellipsis !important;
      white-space: nowrap !important;
      padding: 16px !important;
      box-sizing: border-box !important;
    }
    
    .ant-table-tbody > tr {
      cursor: pointer;
    }
    
    .ant-table-tbody > tr:hover {
      background-color: #f5f5f5;
    }
    
    .ant-table-tbody > tr > td {
      display: table-cell !important;
      word-break: break-all !important;
      word-wrap: break-word !important;
      overflow: hidden !important;
      text-overflow: ellipsis !important;
      white-space: nowrap !important;
      padding: 16px !important;
      box-sizing: border-box !important;
    }
    
    .ant-table-tbody > tr > td > div {
      overflow: hidden;
      text-overflow: ellipsis;
    }
    
    .table-container {
      width: 100%;
      overflow-x: auto;
      overflow-y: auto;
    }
    
    /* 确保滚动条在所有浏览器中可见 */
    .table-container::-webkit-scrollbar {
      -webkit-appearance: none;
      width: 12px;
      height: 12px;
    }
    
    .table-container::-webkit-scrollbar-thumb {
      border-radius: 8px;
      background-color: rgba(0, 0, 0, 0.3);
    }
    
    .table-container::-webkit-scrollbar-track {
      background-color: rgba(0, 0, 0, 0.1);
      border-radius: 8px;
    }
    
    /* Firefox scrollbar */
    .table-container {
      scrollbar-width: thin;
      scrollbar-color: rgba(0, 0, 0, 0.3) rgba(0, 0, 0, 0.1);
    }
    
    /* 分页控件居中 */
    .ant-table-pagination {
      display: flex !important;
      justify-content: center !important;
      margin: 16px 0 !important;
    }
    
    /* 确保分页控件在小屏幕上也能正常显示 */
    .ant-pagination-options {
      margin-left: 8px !important;
    }
    
    .ant-pagination-total-text {
      margin-right: 8px !important;
    }
    
    /* 模态框中的数据展示样式 */
    .data-content {
      word-wrap: break-word;
      white-space: pre-wrap;
      max-height: 300px;
      overflow-y: auto;
      padding: 8px;
      background-color: #f9f9f9;
      border-radius: 4px;
      border: 1px solid #e8e8e8;
    }
    
    .hex-content {
      font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, Courier, monospace;
      font-size: 12px;
      line-height: 1.4;
    }
    
    .tab-content {
      max-height: 60vh;
      overflow-y: auto;
      padding: 16px;
    }
  `;

  return (
    <Content 
      style={{ 
        padding: windowSize.width < 768 ? 12 : 24, 
        background: '#fff',
        width: '100%'
      }}
    >
      <style>{tableHeaderStyle}</style>
      <Row gutter={windowSize.width < 576 ? 8 : 16} style={{ marginBottom: 12 }}>
        <Col>
          <Card size="small">
            <div style={{ 
              fontSize: windowSize.width < 576 ? '10px' : '12px', 
              fontWeight: 500 
            }}>
              状态: {isCapturing ? '捕获中...' : '已停止'}
            </div>
          </Card>
        </Col>
        <Col>
          <Card size="small">
            <div style={{ 
              fontSize: windowSize.width < 576 ? '10px' : '12px', 
              fontWeight: 500 
            }}>
              数据条数: {data.length}
            </div>
          </Card>
        </Col>
      </Row>
      
      <div className="table-container" ref={containerRef} style={{ overflowY: 'auto' }}>
        <Table
          columns={tableColumns}
          dataSource={sortedData}
          pagination={pagination}
          onChange={handleTableChange}
          scroll={{ 
            x: totalWidth,
            y: windowSize.width < 576 
              ? 'calc(100vh - 320px)' 
              : windowSize.height < 768 
                ? 'calc(100vh - 300px)' 
                : 'calc(100vh - 290px)' 
          }}
          size={windowSize.width < 576 ? "small" : "middle"}
          components={components}
          tableLayout="fixed"
          sticky
          style={{ width: '100%' }}
          onRow={(record) => ({
            onClick: () => handleRowClick(record),
          })}
        />
      </div>
      
      <DetailModal 
        visible={detailModalVisible}
        selectedRecord={selectedRecord}
        onClose={closeDetailModal}
        modalWidth={modalWidth}
      />
    </Content>
  );
};

export default DataTable;