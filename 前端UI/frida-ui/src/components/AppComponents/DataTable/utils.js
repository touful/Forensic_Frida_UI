// 数据转换函数
export const convertToHex = (data) => {
  try {
    if (typeof data === 'string') {
      // 将字符串转换为十六进制
      return data.split('').map(char => char.charCodeAt(0).toString(16).padStart(2, '0')).join(' ');
    } else if (typeof data === 'number') {
      return data.toString(16);
    } else {
      return JSON.stringify(data).split('').map(char => char.charCodeAt(0).toString(16).padStart(2, '0')).join(' ');
    }
  } catch (e) {
    return '无法转换为十六进制';
  }
};

export const convertToAscii = (data) => {
  try {
    if (typeof data === 'string') {
      return data;
    } else if (typeof data === 'number') {
      return String.fromCharCode(data);
    } else {
      return JSON.stringify(data);
    }
  } catch (e) {
    return '无法转换为ASCII';
  }
};

// Helper function to check if a string is valid JSON
export const isJSON = (str) => {
  if (typeof str !== 'string') return false;
  try {
    const parsed = JSON.parse(str);
    return typeof parsed === 'object' && parsed !== null;
  } catch (e) {
    return false;
  }
};

// Helper function to format JSON data with syntax highlighting
export const formatJSON = (data) => {
  try {
    // If it's already an object, stringify it
    if (typeof data === 'object' && data !== null) {
      return JSON.stringify(data, null, 2);
    }
    
    // If it's a string, check if it's JSON
    if (typeof data === 'string') {
      if (isJSON(data)) {
        const parsed = JSON.parse(data);
        return JSON.stringify(parsed, null, 2);
      }
      // If not JSON, return as is
      return data;
    }
    
    // For other types, convert to string
    return String(data);
  } catch (e) {
    return String(data);
  }
};