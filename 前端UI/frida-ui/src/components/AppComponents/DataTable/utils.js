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

// 检查是否为数字数组
const isNumericArray = (arr) => {
  if (!Array.isArray(arr)) return false;
  return arr.every(item => typeof item === 'number' || (!isNaN(Number(item)) && isFinite(Number(item))));
};

// 将数字转换为无符号数
const toUnsigned = (num) => {
  const n = Number(num);
  // 处理32位有符号整数转换为无符号
  if (n < 0) {
    return n + 4294967296; // 2^32
  }
  return n;
};

// 将数字数组转换为字符串（通过将每个数字视为字符码）
const numericArrayToString = (arr) => {
  try {
    return arr.map(num => {
      const unsignedNum = toUnsigned(num);
      // 确保在有效的字符码范围内
      if (unsignedNum >= 0 && unsignedNum <= 0x10FFFF) {
        return String.fromCodePoint(unsignedNum);
      }
      return String.fromCharCode(unsignedNum & 0xFFFF); // 限制在16位
    }).join('');
  } catch (e) {
    return arr.join('');
  }
};

// 智能解码函数（类似CyberChef的Magic功能）
export const magicDecode = (data) => {
  if (data === null || data === undefined) {
    return '数据为空';
  }

  // 检查是否为数字数组
  let processedData = data;
  let isNumArray = false;
  
  // 如果是数组，检查是否为数字数组
  if (Array.isArray(data)) {
    if (isNumericArray(data)) {
      isNumArray = true;
      processedData = numericArrayToString(data);
    } else {
      // 如果不是纯数字数组，转换为字符串
      processedData = data.join('');
    }
  } else {
    // 转换为字符串进行处理
    processedData = typeof data === 'string' ? data : JSON.stringify(data);
  }

  // 存储所有可能的解码结果
  const results = [];

  // 1. 原始数据
  if (isNumArray) {
    results.push({ name: '数字数组转字符串', value: processedData, confidence: 95 });
  } else {
    results.push({ name: '原始数据', value: processedData, confidence: 100 });
  }

  // 2. 尝试Base64解码
  try {
    const base64Regex = /^[A-Za-z0-9+/]*={0,2}$/;
    if (base64Regex.test(processedData.replace(/\s/g, '')) && processedData.length % 4 === 0) {
      // 浏览器环境下的Base64解码
      if (typeof atob !== 'undefined') {
        const decoded = atob(processedData);
        results.push({ name: 'Base64解码', value: decoded, confidence: 90 });
      } else if (typeof Buffer !== 'undefined') {
        // Node.js环境下的Base64解码
        const decoded = Buffer.from(processedData, 'base64').toString('binary');
        results.push({ name: 'Base64解码', value: decoded, confidence: 90 });
      }
    }
  } catch (e) {
    // Base64解码失败，跳过
  }

  // 3. 尝试Hex解码
  try {
    const hexRegex = /^[0-9A-Fa-f\s]+$/;
    const cleanHex = processedData.replace(/\s/g, '');
    if (hexRegex.test(cleanHex) && cleanHex.length % 2 === 0) {
      let decoded = '';
      for (let i = 0; i < cleanHex.length; i += 2) {
        const hexPair = cleanHex.substr(i, 2);
        decoded += String.fromCharCode(parseInt(hexPair, 16));
      }
      results.push({ name: 'Hex解码', value: decoded, confidence: 85 });
    }
  } catch (e) {
    // Hex解码失败，跳过
  }

  // 4. 尝试URL解码
  try {
    const decoded = decodeURIComponent(processedData);
    if (decoded !== processedData) {
      results.push({ name: 'URL解码', value: decoded, confidence: 80 });
    }
  } catch (e) {
    // URL解码失败，跳过
  }

  // 5. 尝试UTF-8解码（如果数据看起来像字节序列）
  try {
    if (typeof data === 'string' && data.includes('\\x')) {
      const decoded = processedData.replace(/\\x([0-9A-Fa-f]{2})/g, (match, hex) => {
        return String.fromCharCode(parseInt(hex, 16));
      });
      results.push({ name: 'UTF-8解码', value: decoded, confidence: 75 });
    }
  } catch (e) {
    // UTF-8解码失败，跳过
  }

  // 6. 尝试JSON解析
  try {
    if (typeof processedData === 'string' && (processedData.startsWith('{') && processedData.endsWith('}') || 
                                    processedData.startsWith('[') && processedData.endsWith(']'))) {
      const parsed = JSON.parse(processedData);
      results.push({ name: 'JSON解析', value: JSON.stringify(parsed, null, 2), confidence: 70 });
    }
  } catch (e) {
    // JSON解析失败，跳过
  }

  // 根据置信度排序
  results.sort((a, b) => b.confidence - a.confidence);

  // 返回置信度最高的结果
  if (results.length > 1) {
    return `${results[0].name} (置信度: ${results[0].confidence}%)\n${results[0].value}\n\n` +
           `其他可能的解码:\n` +
           results.slice(1).map(r => `${r.name} (置信度: ${r.confidence}%)\n${r.value}`).join('\n\n');
  } else {
    return `${results[0].name}\n${results[0].value}`;
  }
};