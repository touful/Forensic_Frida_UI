const WebSocket = require('ws');

// 创建WebSocket服务器
const wss = new WebSocket.Server({ port: 8080 });

// 存储所有连接的客户端
const clients = new Set();

wss.on('connection', (ws) => {
  console.log('新客户端已连接');
  clients.add(ws);
  
  // 当服务器收到消息时
  ws.on('message', (message) => {
    console.log('收到消息:', message);
    
    // 将消息转发给所有连接的客户端
    clients.forEach(client => {
      if (client !== ws && client.readyState === WebSocket.OPEN) {
        client.send(message);
      }
    });
  });
  
  // 当客户端断开连接时
  ws.on('close', () => {
    console.log('客户端已断开连接');
    clients.delete(ws);
  });
  
  // 发送连接成功的消息
  ws.send(JSON.stringify({
    type: 'connection_status',
    status: 'connected'
  }));
});

console.log('WebSocket服务器运行在端口8080');