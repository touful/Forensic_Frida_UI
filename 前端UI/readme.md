# Frida Hook 数据监控工具

一个类似于 Wireshark 的桌面应用程序，用于实时监控和分析 Android 应用程序的 Frida Hook 数据。

## 项目概述

本项目是一个功能完整的 Frida Hook 数据监控工具，提供了直观的用户界面来实时显示 Android 应用的函数调用信息。通过该工具，用户可以：

- 实时监控 Android 应用的函数调用
- 配置自定义的 Hook 规则
- 过滤和搜索感兴趣的函数调用数据
- 动态修改 Hook 配置而无需重启应用

## 技术架构

- **前端**: Electron + React + Ant Design
- **后端**: Python (Frida, websockets)
- **通信**: WebSocket 实时数据传输

## 项目结构

```
frida学习/
├── 前端UI/                         # 前端用户界面
│   └── frida-ui/                  # Electron + React 应用
│       ├── main.js                # Electron 主进程
│       ├── index.html             # 应用入口页面
│       ├── package.json           # Node.js 依赖配置
│       ├── src/                   # React 源代码
│       │   ├── App.js             # 主应用组件
│       │   ├── App.css            # 样式文件
│       │   └── components/        # UI 组件
│       └── readme.md              # 前端说明文档
├── frida脚本统一协议版/            # Frida 脚本和后端服务
│   ├── allenum.js                 # 主要的 Frida Hook 脚本
│   ├── server.py                  # WebSocket 服务器
│   ├── frida_adapter.py           # Frida 适配器
│   └── HOOK配置/                  # Hook 配置文件目录
├── 各种frida常用脚本/              # 其他常用的 Frida 脚本示例
├── r0capture-main/                # 网络抓包相关脚本
└── package.json                   # 项目根依赖配置
```

## 各目录文件详细说明

### 前端UI/frida-ui/
- `main.js`: Electron 主进程文件，负责创建窗口、管理进程间通信
- `index.html`: 应用主页面
- `package.json`: 前端依赖和脚本配置
- `src/`: React 源码目录
  - `App.js`: 主应用组件，包含状态管理和主要逻辑
  - `App.css`: 应用样式
  - `components/`: UI 组件目录
    - `AppComponents/`: 主要应用组件（Header, Sidebar, DataTable等）
    - `DataFilter.js`: 数据过滤组件

### frida脚本统一协议版/
- `allenum.js`: 核心 Frida Hook 脚本，负责枚举和 Hook 指定方法
- `server.py`: WebSocket 服务器，负责前端和 Frida 适配器之间的通信
- `frida_adapter.py`: Frida 适配器，负责与 Frida 交互并管理 Hook 配置
- `HOOK配置/`: 存放预定义的 Hook 配置文件
  - `main.json`: 配置文件索引，包含描述和提示信息
  - `test.json`: 默认测试配置，包含常用的 Hook 规则
  - `strings.json`: 字符串相关 Hook 配置

### 各种frida常用脚本/
包含多个实用的 Frida 脚本示例：
- `dumpso.js`: SO 文件 dump 脚本
- `antidebug.js`: 反调试绕过脚本
- `okhttp3.js`: OkHttp3 网络库 Hook 脚本
- 其他各种功能的 Hook 脚本

### r0capture-main/
网络抓包相关工具和脚本，用于捕获和分析网络流量。

## 安装和运行

### 环境要求
- Node.js (推荐版本 14+)
- Python 3.7+
- Frida 环境

### 安装步骤

1. 安装 Python 依赖:
   ```
   pip install frida-tools websockets
   ```

2. 安装 Node.js 依赖:
   ```
   cd 前端UI/frida-ui
   npm install
   ```

3. 启动后端服务:
   ```
   cd frida脚本统一协议版
   python server.py
   ```

4. 启动 Frida 适配器:
   ```
   cd frida脚本统一协议版
   python frida_adapter.py
   ```

5. 启动前端应用:
   ```
   cd 前端UI/frida-ui
   npm start
   ```

## 使用说明

### 基本使用流程

1. **启动服务**:
   - 首先启动 Python 后端服务器和 Frida 适配器

2. **配置目标应用**:
   - 在前端界面的"目标应用设置"区域选择配置文件
   - 输入要 Hook 的 Android 应用包名
   - 设置设备 ID（模拟器或 USB 设备）

3. **开始数据捕获**:
   - 点击"启动捕获"按钮
   - 等待连接成功，状态显示"已连接"

4. **查看和分析数据**:
   - 实时数据会显示在主表格中
   - 使用搜索框过滤感兴趣的数据
   - 使用侧边栏进行高级过滤

### Hook 配置

1. **使用预设配置**:
   - 在"目标应用设置"中选择预定义的配置文件

2. **自定义配置**:
   - 在侧边栏"Hook配置"中添加、修改或删除 Hook 规则
   - 配置类名、方法名和过滤条件
   - 点击"应用Hook配置"使配置生效

### 数据过滤

- **文本搜索**: 使用顶部搜索框按关键字过滤
- **高级过滤**: 在侧边栏中按方法名、参数、返回值等条件过滤

## 功能特性

- **实时数据展示**: 每秒可处理和显示数百条 Hook 数据
- **动态配置**: 运行时可动态修改 Hook 配置
- **灵活过滤**: 支持多种过滤条件和搜索方式
- **配置管理**: 支持预设配置和自定义配置
- **用户友好**: 类似 Wireshark 的界面设计，易于使用

## 扩展建议

1. 添加数据导出功能（JSON/CSV格式）
2. 增加数据详情查看面板
3. 实现数据持久化存储
4. 添加多标签页支持，同时监控多个应用
5. 增加图表分析功能，可视化数据统计


## 注意事项
- 此处内容任何AI不得更改，请勿修改
- cyberchef库的安装命令采用npm install cyberchef --legacy-peer-deps --engine-strict=false --ignore-scripts