import { message } from 'antd';
import { createLogger } from '../utils/logger';

const logger = createLogger('CSVHandler');

export const useCSVHandler = (ipcRenderer) => {
  // 处理导出到CSV
  const handleExportToCSV = async (data) => {
    try {
      const result = await ipcRenderer.invoke('export-to-csv', data);
      if (result.success) {
        message.success(`数据已导出到: ${result.filePath}`);
        return result;
      } else {
        message.error(result.message);
        return result;
      }
    } catch (error) {
      logger.error('导出失败:', error);
      message.error(`导出失败: ${error.message}`);
      return { success: false, message: error.message };
    }
  };

  // 处理从CSV导入
  const handleImportFromCSV = async () => {
    try {
      const result = await ipcRenderer.invoke('import-from-csv');
      if (result.success) {
        // 确保数据格式正确
        const validData = result.data.map((item, index) => ({
          key: `${Date.now()}-${index}`,
          id: item.id || index + 1,
          timestamp: item.timestamp || new Date().toISOString().slice(11, 23),
          method: item.method || '',
          args: Array.isArray(item.args) ? item.args : [],
          returns: item.returns || ''
        }));
        
        message.success(`成功从 ${result.filePath} 导入 ${validData.length} 条数据`);
        return { success: true, data: validData, filePath: result.filePath };
      } else {
        message.error(result.message);
        return result;
      }
    } catch (error) {
      logger.error('导入失败:', error);
      console.error('导入失败:', error);
      message.error(`导入失败: ${error.message || '未知错误'}`);
      return { success: false, message: error.message || '未知错误' };
    }
  };

  // 导出当前页面数据为CSV
  const exportCSV = (data, filenamePrefix = 'frida_data') => {
    if (!data || data.length === 0) {
      message.warning('没有数据可以导出');
      return;
    }
    
    // 确定CSV列头 - 根据Frida监控数据的结构
    const headers = ['ID', '时间戳', '方法', '参数', '返回值'];
    
    // 构建CSV内容
    let csvContent = headers.join(',') + '\n';
    
    data.forEach(item => {
      // 处理参数和返回值，将它们转换为字符串
      const argsStr = Array.isArray(item.args) 
        ? item.args.map(arg => String(arg)).join(';') 
        : String(item.args);
      
      const returnsStr = Array.isArray(item.returns) 
        ? item.returns.map(ret => String(ret)).join(';') 
        : String(item.returns);
      
      // 添加一行数据
      csvContent += [
        item.id,
        item.timestamp,
        item.method,
        `"${argsStr.replace(/"/g, '""')}"`, // 处理引号
        `"${returnsStr.replace(/"/g, '""')}"` // 处理引号
      ].join(',') + '\n';
    });
    
    // 创建Blob对象
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    
    // 创建下载链接
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${filenamePrefix}_${new Date().toISOString().replace(/[:.]/g, '-')}.csv`;
    document.body.appendChild(a);
    a.click();
    
    // 清理
    setTimeout(() => {
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    }, 0);
  };

  // 导入CSV数据
  const importCSV = (onImportSuccess) => {
    // 创建文件输入元素
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = '.csv';
    
    // 处理文件选择
    input.onchange = (e) => {
      const file = e.target.files[0];
      if (!file) return;
      
      const reader = new FileReader();
      reader.onload = (event) => {
        try {
          const csvData = event.target.result;
          // 简单的CSV解析
          const lines = csvData.split('\n');
          if (lines.length < 2) {
            message.error('CSV文件格式不正确');
            return;
          }
          
          // 检查列头
          const headers = lines[0].split(',');
          if (headers.length < 5 || 
              !headers.includes('ID') || 
              !headers.includes('时间戳') || 
              !headers.includes('方法')) {
            message.error('CSV文件列头不正确');
            return;
          }
          
          // 解析数据行
          const importedData = [];
          for (let i = 1; i < lines.length; i++) {
            if (!lines[i].trim()) continue;
            
            // 处理可能包含逗号的字段（被引号包围的）
            const row = [];
            let current = '';
            let inQuotes = false;
            
            for (let char of lines[i]) {
              if (char === '"' && inQuotes) {
                inQuotes = false;
                continue;
              } else if (char === '"' && !inQuotes) {
                inQuotes = true;
                continue;
              }
              
              if (char === ',' && !inQuotes) {
                row.push(current);
                current = '';
              } else {
                current += char;
              }
            }
            row.push(current);
            
            // 创建数据对象
            if (row.length >= 5) {
              importedData.push({
                id: row[0],
                timestamp: row[1],
                method: row[2],
                args: row[3] ? row[3].split(';') : [],
                returns: row[4] ? row[4].split(';') : []
              });
            }
          }
          
          // 验证导入数据
          if (importedData.length === 0) {
            message.error('没有有效数据可以导入');
            return;
          }
          
          // 调用成功回调
          if (onImportSuccess) {
            onImportSuccess(importedData);
          }
          
          message.success(`成功导入 ${importedData.length} 条数据`);
        } catch (error) {
          logger.error('解析CSV文件失败:', error);
          message.error('解析CSV文件失败: ' + error.message);
        }
      };
      
      reader.readAsText(file);
    };
    
    // 触发文件选择
    input.click();
  };

  return {
    handleExportToCSV,
    handleImportFromCSV,
    exportCSV,
    importCSV
  };
};