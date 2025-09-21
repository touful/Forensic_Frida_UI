// Frida脚本适配器
// 该脚本用于连接真实的Frida脚本和WebSocket服务器
const frida = require('frida');
const WebSocket = require('ws');

// 创建WebSocket服务器
const wss = new WebSocket.Server({ port: 8081 });

// 存储连接的客户端
const clients = new Set();

console.log('Frida适配器服务器运行在端口8081');

wss.on('connection', (ws) => {
  console.log('客户端已连接');
  clients.add(ws);
  
  // 当客户端发送消息时，可能是Frida脚本的配置信息
  ws.on('message', (message) => {
    console.log('收到客户端消息:', message);
    try {
      const config = JSON.parse(message);
      if (config.type === 'attach') {
        attachToProcess(config.target);
      }
    } catch (e) {
      console.error('解析客户端消息失败:', e);
    }
  });
  
  ws.on('close', () => {
    console.log('客户端断开连接');
    clients.delete(ws);
  });
});

// 将数据发送给所有连接的客户端
function sendData(data) {
  const message = JSON.stringify(data);
  clients.forEach(client => {
    if (client.readyState === WebSocket.OPEN) {
      client.send(message);
    }
  });
}

// 附加到目标进程
async function attachToProcess(target) {
  try {
    let session;
    
    // 根据目标类型（PID或包名）附加到进程
    if (typeof target === 'number') {
      // 通过PID附加
      session = await frida.attach(target);
    } else {
      // 通过名称附加
      session = await frida.attach(target);
    }
    
    console.log(`成功附加到进程: ${target}`);
    
    // 创建并加载脚本
    const script = await session.createScript(`
      // 重写send函数，将数据发送到Node.js层
      var originalSend = send;
      
      // 你的Frida脚本内容（从allenum.js简化而来）
      var methods_names=[
        {
          class: "java.lang.String",
          method: "compareTo",
          avoid_args: [{
            "front": ["CN","zh"],
            "back": [],
            "matchall": [""]
          }],
          avoid_returns: []
        },
        {
          class: "java.lang.String",
          method: "equals",
          avoid_args: [{
            "front": ["res/layout/","layout_"],
            "back": [],
            "matchall": ["","und","display","autofill","sound_effects_enabled",
                "LinearLayout","TextView","UTF-8"
            ]
          }],
          avoid_returns: []
        },
        {
          class: "java.lang.StringFactory",
          method: "newStringFromString",
          avoid_args: [],
          avoid_returns: []
        },
        {
          class: "android.util.Base64",
          method: "encodeToString",
          avoid_args: [],
          avoid_returns: []
        },
        {
          class: "android.util.Base64",
          method: "decode",
          avoid_args: [],
          avoid_returns: []
        },
        {
          class: "javax.crypto.Cipher",
          method: "doFinal",
          avoid_args: [],
          avoid_returns: []
        },
      ];
      
      // 简化的hook实现
      function setupHooks() {
        // 这里应该实现完整的hook逻辑
        // 为简化示例，我们只发送测试数据
        setInterval(() => {
          var testData = {
            method: "java.lang.String.equals",
            args: ["test", "test"],
            returns: "true",
            timestamp: new Date().toISOString()
          };
          send(testData);
        }, 1000);
      }
      
      // 当脚本加载完成时执行
      rpc.exports.init = function() {
        setupHooks();
        return "Hooks设置完成";
      };
    `);
    
    // 处理来自Frida脚本的消息
    script.message.connect(message => {
      if (message.type === 'send') {
        console.log('收到Frida数据:', message.payload);
        sendData(message.payload);
      } else if (message.type === 'error') {
        console.error('Frida脚本错误:', message.description);
      } else {
        console.log('收到其他消息:', message);
      }
    });
    
    // 加载脚本
    await script.load();
    
    // 初始化脚本
    await script.exports.init();
    
    console.log('Frida脚本加载完成');
    
  } catch (e) {
    console.error('附加到进程失败:', e);
  }
}

// 暴露接口给主服务器
module.exports = {
  sendData
};