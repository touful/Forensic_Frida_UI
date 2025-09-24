import { useState, useEffect } from 'react';
import { createLogger } from '../utils/logger';

// 定义常量
const CONFIG_DIR_NAME = 'HOOK配置';
const MAIN_CONFIG_FILE = 'main.json';
const FRIDA_SCRIPT_DIR = 'frida脚本统一协议版';

const logger = createLogger('ConfigFiles');

export const useConfigFiles = (ipcRenderer, isMounted) => {
  const [configFiles, setConfigFiles] = useState([]);
  const [selectedConfig, setSelectedConfig] = useState('');
  const [hookConfigs, setHookConfigs] = useState([]);

  // 获取配置文件列表
  const getConfigFiles = async () => {
    try {
      // 获取项目根路径
      const rootPath = await ipcRenderer.invoke('get-root-path');
      
      const path = window.require('path');
      const fs = window.require('fs');
      
      // 使用path.join构建规范路径
      const configDir = path.join(rootPath, FRIDA_SCRIPT_DIR, CONFIG_DIR_NAME);
      
      // 检查目录是否存在
      const dirExists = await new Promise((resolve) => {
        fs.access(configDir, fs.constants.F_OK, (err) => {
          resolve(!err);
        });
      });
      
      if (!dirExists) {
        logger.error('配置目录不存在:', configDir);
        return;
      }
      
      // 使用Promise包装异步操作
      const files = await new Promise((resolve, reject) => {
        fs.readdir(configDir, (err, files) => {
          if (err) {
            logger.error('读取配置目录失败:', err);
            reject(err);
          } else {
            resolve(files);
          }
        });
      });
      
      // 明确过滤出.json文件（排除main.json）
      const jsonFiles = files.filter(file => 
        path.extname(file).toLowerCase() === '.json' && file.toLowerCase() !== MAIN_CONFIG_FILE
      );
      
      // 构造基本的配置文件列表
      let configFilesWithTips = jsonFiles.map(file => ({
        name: file,
        description: file,
        tips: ''
      }));
      
      try {
        // 尝试读取main.json获取提示词信息
        const mainJsonData = await new Promise((resolve, reject) => {
          const mainJsonPath = path.join(configDir, MAIN_CONFIG_FILE);
          
          // 检查main.json是否存在
          fs.access(mainJsonPath, fs.constants.F_OK, (err) => {
            if (err) {
              resolve('{}'); // 返回空的JSON对象
            } else {
              fs.readFile(mainJsonPath, 'utf8', (err, data) => {
                if (err) {
                  logger.error('读取main.json失败:', err);
                  reject(err);
                } else {
                  resolve(data);
                }
              });
            }
          });
        });
        
        const mainConfig = JSON.parse(mainJsonData);
        configFilesWithTips = jsonFiles.map(file => {
          const configInfo = mainConfig[file] || {};
          return {
            name: file,
            description: configInfo.description || file,
            tips: configInfo.tips || ''
          };
        });
      } catch (parseError) {
        logger.error('解析main.json失败:', parseError);
      }
      
      // 检查组件是否仍然挂载
      if (isMounted.current) {
        setConfigFiles(configFilesWithTips);
        
        // 如果有配置文件，默认选择第一个
        if (configFilesWithTips.length > 0 && !selectedConfig) {
          setSelectedConfig(configFilesWithTips[0].name);
        }
      }
    } catch (error) {
      logger.error('获取配置文件列表失败:', error);
    }
  };

  // 当选中的配置文件改变时，读取配置文件内容
  const loadConfigFileContent = async (selectedConfigFile, configFilesList) => {
    if (selectedConfigFile && configFilesList && configFilesList.length > 0) {
      try {
        const rootPath = await ipcRenderer.invoke('get-root-path');
        const path = window.require('path');
        const fs = window.require('fs');
        const configDir = path.join(rootPath, FRIDA_SCRIPT_DIR, CONFIG_DIR_NAME);
        const configPath = path.join(configDir, selectedConfigFile);
        
        // 读取配置文件内容
        fs.readFile(configPath, 'utf8', (err, data) => {
          if (err) {
            logger.error('读取配置文件失败:', err);
            if (isMounted.current) {
              setHookConfigs([]);
            }
          } else {
            try {
              const configData = JSON.parse(data);
              if (isMounted.current) {
                setHookConfigs(configData);
              }
            } catch (parseError) {
              logger.error('解析配置文件失败:', parseError);
              if (isMounted.current) {
                setHookConfigs([]);
              }
            }
          }
        });
      } catch (error) {
        logger.error('加载配置文件内容失败:', error);
        if (isMounted.current) {
          setHookConfigs([]);
        }
      }
    } else {
      if (isMounted.current) {
        setHookConfigs([]);
      }
    }
  };

  return {
    configFiles,
    setConfigFiles,
    selectedConfig,
    setSelectedConfig,
    hookConfigs,
    setHookConfigs,
    getConfigFiles,
    loadConfigFileContent
  };
};