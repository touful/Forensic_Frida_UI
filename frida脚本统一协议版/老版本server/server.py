import asyncio
import websockets
import json

# 存储WebSocket连接
connected_clients = set()
# Frida适配器连接
frida_adapter = None

# 处理前端WebSocket连接
async def handle_client(websocket, path):
    global frida_adapter, connected_clients
    
    print(f"客户端已连接: {websocket}")
    connected_clients.add(websocket)    
    try:
        async for message in websocket:
            print(f"收到客户端消息: {message}")
            # 将消息转发给Frida适配器（如果是配置命令）
            await handle_client_command(websocket, message)
    except websockets.exceptions.ConnectionClosed:
        print(f"客户端 {websocket} 连接已关闭")
    except Exception as e:
        print(f"处理客户端 {websocket} 消息时出错: {e}")
        import traceback
        traceback.print_exc()
    finally:
        connected_clients.remove(websocket)
        print(f"客户端 {websocket} 已断开连接")
        print(f"当前连接客户端数: {len(connected_clients)}")
        if frida_adapter == websocket:
            frida_adapter = None
            print("Frida适配器断开连接")
        print("客户端断开连接处理完成")

# 处理来自客户端的命令
async def handle_client_command(sender, message):
    global frida_adapter
    
    try:
        command = json.loads(message)
        command_type = command.get("type")
        print(f"处理命令类型: {command_type}")
        print(f"当前Frida适配器: {frida_adapter}")        
        # 如果是发送给Frida适配器的命令，转发过去
        if command_type in ["hook_config", "start_capture"]:
            if frida_adapter and frida_adapter != sender:
                print(f"转发命令 {command_type} 到Frida适配器")
                await frida_adapter.send(message)
            else:
                print(f"无法转发命令 {command_type}，没有可用的Frida适配器或发送者就是适配器")
        # 如果是Frida适配器的注册消息
        elif command_type == "register_adapter":
            print("处理注册适配器消息")
            frida_adapter = sender
            print("Frida适配器已注册")
        # 如果是Frida数据，转发给除发送者外的所有客户端
        elif command_type == "frida_data":
            print("转发Frida数据到前端客户端")
            # 转发给除发送者外的所有客户端
            clients_to_send = [client for client in connected_clients if client != sender]
            if clients_to_send:
                await asyncio.gather(
                    *[client.send(message) for client in clients_to_send],
                    return_exceptions=True
                )
        else:
            print(f"未知命令类型: {command_type}")
            
    except json.JSONDecodeError:
        print("无法解析WebSocket消息为JSON")
    except Exception as e:
        print(f"处理WebSocket消息时出错: {e}")
        import traceback
        traceback.print_exc()

# 启动WebSocket服务器
async def main():
    # 启动WebSocket服务器
    async with websockets.serve(handle_client, "localhost", 8080):
        print("WebSocket服务器运行在 localhost:8080")
        await asyncio.Future()  # 运行直到被中断

if __name__ == "__main__":
    # 启动WebSocket服务器
    asyncio.run(main())