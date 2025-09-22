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

// 使用CyberChef的Magic功能
export const magicDecode = (data) => {
  // 检查是否在浏览器环境中
  if (typeof window !== 'undefined') {
    try {
      // 动态导入CyberChef
      const Chef = require("cyberchef");
      
      // 将数据转换为字符串格式
      let dataStr = '';
      if (Array.isArray(data)) {
        // 如果是数组，检查是否为数字数组
        const isNumericArray = data.every(item => typeof item === 'number' || (!isNaN(Number(item)) && isFinite(Number(item))));
        if (isNumericArray) {
          // 将数字数组转换为无符号数再转为字符串
          dataStr = data.map(num => {
            const n = Number(num);
            // 转换为无符号32位整数
            const unsignedNum = n < 0 ? n + 4294967296 : n;
            try {
              // 尝试使用完整的Unicode范围
              if (unsignedNum >= 0 && unsignedNum <= 0x10FFFF) {
                return String.fromCodePoint(unsignedNum);
              }
              // 如果超出范围，使用16位字符码
              return String.fromCharCode(unsignedNum & 0xFFFF);
            } catch (e) {
              // fallback到数字本身
              return String(num);
            }
          }).join('');
        } else {
          // 非数字数组直接转换为字符串
          dataStr = data.join('');
        }
      } else {magic
        // 非数组直接转换为字符串
        dataStr = typeof data === 'string' ? data : JSON.stringify(data);
      }
      
      // 使用CyberChef的Magic函数
      const magic = Chef.magic(dataStr, false);
      
      // 格式化结果
      if (magic.length > 0) {
        let result = '';
        // 显示最佳结果
        const bestResult = magic[0];
        result += `${bestResult.recipe[0].op} (置信度: ${Math.round(bestResult.confidence * 100)}%)\n`;
        result += `${bestResult.result}\n\n`;
        
        // 如果有其他可能的结果，也显示出来
        if (magic.length > 1) {
          result += '其他可能的解码:\n';
          for (let i = 1; i < Math.min(magic.length, 5); i++) { // 最多显示前5个
            const altResult = magic[i];
            result += `${altResult.recipe[0].op} (置信度: ${Math.round(altResult.confidence * 100)}%)\n`;
            result += `${altResult.result}\n\n`;
          }
        }
        
        return result.trim();
      } else {
        return '原始数据\n' + dataStr;
      }
    } catch (e) {
      // CyberChef处理失败时的回退方案
      return 'CyberChef处理失败: ' + e.message + '\n\n原始数据:\n' + (typeof data === 'string' ? data : JSON.stringify(data, null, 2));
    }
  } else {
    // 非浏览器环境或CyberChef不可用时的回退方案
    return 'CyberChef在当前环境中不可用\n\n原始数据:\n' + (typeof data === 'string' ? data : JSON.stringify(data, null, 2));
  }
};