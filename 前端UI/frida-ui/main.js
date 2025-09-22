const { app, BrowserWindow, ipcMain, Menu, dialog, nativeTheme } = require('electron');
const path = require('path');
const { spawn } = require('child_process');
const fs = require('fs');

let serverProcess = null;

// 处理获取项目根路径的请求
ipcMain.handle('get-root-path', async (event, ...args) => {
  // 获取项目根目录（当前目录的上级目录）
  const rootPath = path.join(__dirname, '../..');
  console.log('获取到的项目根路径:', rootPath);
  return rootPath;
});

// 处理获取ADB设备列表的请求
ipcMain.handle('get-adb-devices', async (event, ...args) => {
  try {
    // 获取项目根目录
    const rootPath = path.join(__dirname, '../..');
    // 构建adb.exe的路径
    const adbPath = path.join(rootPath, 'androidtool', 'adb.exe');
    
    // 执行adb devices命令
    const adbProcess = spawn(adbPath, ['devices'], { cwd: path.dirname(adbPath) });
    
    let stdoutData = '';
    let stderrData = '';
    
    adbProcess.stdout.on('data', (data) => {
      stdoutData += data.toString();
    });
    
    adbProcess.stderr.on('data', (data) => {
      stderrData += data.toString();
    });
    
    // 等待命令执行完成
    const exitCode = await new Promise((resolve) => {
      adbProcess.on('close', resolve);
    });
    
    if (exitCode !== 0) {
      throw new Error(`ADB命令执行失败: ${stderrData}`);
    }
    
    // 解析设备列表
    const devices = [];
    const lines = stdoutData.trim().split('\n');
    
    // 跳过第一行"List of devices attached"
    for (let i = 1; i < lines.length; i++) {
      const line = lines[i].trim();
      if (line && !line.startsWith('*') && line.includes('device')) {
        // 提取设备ID（第一列）
        const deviceId = line.split(/\s+/)[0];
        if (deviceId) {
          devices.push(deviceId);
        }
      }
    }
    
    return { success: true, devices: devices };
  } catch (error) {
    console.error('获取ADB设备列表时出错:', error);
    return { success: false, error: error.message };
  }
});

// 处理导出数据到CSV的请求
ipcMain.handle('export-to-csv', async (event, data) => {
  try {
    // 显示保存对话框
    const result = await dialog.showSaveDialog({
      title: '导出数据到CSV',
      defaultPath: 'frida_data.csv',
      filters: [
        { name: 'CSV Files', extensions: ['csv'] },
        { name: 'All Files', extensions: ['*'] }
      ]
    });

    if (result.canceled) {
      return { success: false, message: '用户取消了操作' };
    }

    // 构建CSV内容
    let csvContent = 'ID,时间戳,方法,参数,返回值\n';
    
    // 添加数据行
    data.forEach(item => {
      const id = item.id || '';
      const timestamp = item.timestamp || '';
      const method = `"${(item.method || '').replace(/"/g, '""')}"`;
      const args = `"${JSON.stringify(item.args || []).replace(/"/g, '""')}"`;
      const returns = `"${(item.returns || '').replace(/"/g, '""')}"`;
      
      csvContent += `${id},${timestamp},${method},${args},${returns}\n`;
    });

    // 写入文件
    fs.writeFileSync(result.filePath, csvContent, 'utf8');
    
    return { success: true, message: '数据导出成功', filePath: result.filePath };
  } catch (error) {
    console.error('导出CSV时出错:', error);
    return { success: false, message: `导出失败: ${error.message}` };
  }
});

// 处理从CSV导入数据的请求
ipcMain.handle('import-from-csv', async (event) => {
  try {
    // 显示打开文件对话框
    const result = await dialog.showOpenDialog({
      title: '从CSV导入数据',
      filters: [
        { name: 'CSV Files', extensions: ['csv'] },
        { name: 'All Files', extensions: ['*'] }
      ],
      properties: ['openFile']
    });

    if (result.canceled) {
      return { success: false, message: '用户取消了操作' };
    }

    // 读取文件内容
    const csvContent = fs.readFileSync(result.filePaths[0], 'utf8');
    
    // 解析CSV内容
    const lines = csvContent.trim().split('\n');
    
    // 检查是否有内容
    if (lines.length < 1) {
      return { success: false, message: 'CSV文件为空' };
    }
    
    const headers = lines[0].split(',');
    
    // 检查头部是否符合预期格式
    if (headers.length < 5) {
      return { success: false, message: 'CSV文件格式不正确，列数不足' };
    }
    
    const data = [];
    // 从第二行开始处理数据行
    for (let i = 1; i < lines.length; i++) {
      if (lines[i].trim()) {
        try {
          // 简单处理，实际项目中可能需要更复杂的CSV解析
          const values = lines[i].split(/,(?=(?:(?:[^"]*"){2})*[^"]*$)/); // 处理引号内的逗号
          
          // 确保有足够的值
          while (values.length < 5) {
            values.push('');
          }
          
          // 清理引号并解析参数
          const argsString = values[3] || '[]';
          let args = [];
          try {
            // 处理可能被引号包裹的JSON字符串
            const cleanArgsString = argsString.replace(/^"(.*)"$/, '$1').replace(/""/g, '"');
            args = JSON.parse(cleanArgsString);
            // 确保args是数组
            if (!Array.isArray(args)) {
              args = [];
            }
          } catch (e) {
            console.warn('解析参数时出错:', e);
            args = [];
          }
          
          // 清理method和returns字段中的引号
          const cleanMethod = values[2] ? values[2].replace(/^"(.*)"$/, '$1').replace(/""/g, '"') : '';
          const cleanReturns = values[4] ? values[4].replace(/^"(.*)"$/, '$1').replace(/""/g, '"') : '';
          
          const item = {
            id: parseInt(values[0]) || (i), // 使用行号作为默认ID
            timestamp: values[1] || new Date().toISOString().slice(11, 23),
            method: cleanMethod,
            args: args,
            returns: cleanReturns
          };
          
          data.push(item);
        } catch (lineError) {
          console.warn(`解析第${i + 1}行时出错:`, lineError);
          // 跳过这一行但继续处理其他行
        }
      }
    }
    
    return { success: true, message: '数据导入成功', data: data, filePath: result.filePaths[0] };
  } catch (error) {
    console.error('导入CSV时出错:', error);
    return { success: false, message: `导入失败: ${error.message || '未知错误'}` };
  }
});

function createWindow () {
  // 创建浏览器窗口
  const mainWindow = new BrowserWindow({
    width: 1200,
    height: 800,
    webPreferences: {
      nodeIntegration: true,
      contextIsolation: false,
      enableRemoteModule: true,
      webSecurity: false
    }
  });

  // 加载应用的index.html
  mainWindow.loadFile('index.html');

  // 打开开发工具
  // mainWindow.webContents.openDevTools();
  
  // 创建菜单
  createMenu(mainWindow);
}

// 创建中文菜单
function createMenu(mainWindow) {
  const template = [
    {
      label: '文件',
      submenu: [
        {
          label: '导出到CSV',
          click: async () => {
            // 向渲染进程发送导出请求
            mainWindow.webContents.send('request-export-data');
          }
        },
        {
          label: '从CSV导入',
          click: async () => {
            // 向渲染进程发送导入请求
            mainWindow.webContents.send('request-import-data');
          }
        },
        { type: 'separator' },
        {
          label: '重新加载',
          accelerator: 'CmdOrCtrl+R',
          click: () => mainWindow.reload()
        },
        {
          label: '关闭',
          accelerator: 'CmdOrCtrl+W',
          click: () => mainWindow.close()
        }
      ]
    },
    {
      label: '编辑',
      submenu: [
        { role: 'undo', label: '撤销' },
        { role: 'redo', label: '重做' },
        { type: 'separator' },
        { role: 'cut', label: '剪切' },
        { role: 'copy', label: '复制' },
        { role: 'paste', label: '粘贴' },
        { role: 'delete', label: '删除' },
        { role: 'selectAll', label: '全选' }
      ]
    },
    {
      label: '视图',
      submenu: [
        { role: 'reload', label: '重新加载' },
        { role: 'forceReload', label: '强制重新加载' },
        { role: 'toggleDevTools', label: '切换开发者工具' },
        { type: 'separator' },
        { role: 'resetZoom', label: '重置缩放' },
        { role: 'zoomIn', label: '放大' },
        { role: 'zoomOut', label: '缩小' },
        { type: 'separator' },
        { role: 'togglefullscreen', label: '切换全屏' }
      ]
    },
    {
      label: '窗口',
      submenu: [
        { role: 'minimize', label: '最小化' },
        { role: 'zoom', label: '缩放' },
        { role: 'close', label: '关闭' }
      ]
    },
    {
      label: '帮助',
      submenu: [
        {
          label: '学习更多',
          click: async () => {
            const { shell } = require('electron');
            await shell.openExternal('https://github.com/frida');
          }
        }
      ]
    }
  ];

  const menu = Menu.buildFromTemplate(template);
  Menu.setApplicationMenu(menu);
}

// 当Electron完成初始化并准备创建浏览器窗口时调用此方法
app.whenReady().then(() => {
  // 强制使用浅色主题
  nativeTheme.themeSource = 'light';
  
  // 启动WebSocket服务器
  startServer();
  
  createWindow();
  
  app.on('activate', function () {
    // 通常在macOS上，当点击dock图标且没有其他窗口打开时，会重新创建一个窗口
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

// 当所有窗口都关闭时退出应用
app.on('window-all-closed', function () {
  // 在macOS上，除非用户用Cmd + Q明确退出，否则应用会保持活动状态
  if (process.platform !== 'darwin') {
    stopServer();
    app.quit();
  }
});

app.on('before-quit', () => {
  stopServer();
});

function startServer() {
  const serverPath = path.join(__dirname, 'server.js');
  serverProcess = spawn('node', [serverPath], { cwd: __dirname });
  
  serverProcess.stdout.on('data', (data) => {
    // 处理中文乱码问题
    const text = Buffer.from(data).toString('utf8');
    console.log(`[服务器] ${text}`);
  });
  
  serverProcess.stderr.on('data', (data) => {
    // 处理中文乱码问题
    const text = Buffer.from(data).toString('utf8');
    console.error(`[服务器错误] ${text}`);
  });
  
  serverProcess.on('close', (code) => {
    console.log(`[服务器关闭] 退出码: ${code}`);
  });
  
  console.log('WebSocket服务器已启动');
}

function stopServer() {
  if (serverProcess) {
    serverProcess.kill();
    console.log('WebSocket服务器已停止');
  }
}