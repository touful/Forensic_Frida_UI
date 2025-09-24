import asyncio
import websockets
import json
from frida_utils import FridaManager

# 全局变量
connected_clients = set()
main_loop = None
frida_manager = None

class WebSocketMessageSender:
    @staticmethod
    def send_to_all(frida_data):
        global main_loop, connected_clients
        if main_loop and main_loop.is_running():
            for client in connected_clients:
                try:
                    asyncio.run_coroutine_threadsafe(
                        client.send(json.dumps(frida_data)), 
                        main_loop
                    )
                except Exception as e:
                    print(f"向客户端 {client} 发送消息时出错: {e}")
# 事件处理函数
async def handle_start_capture_event(sender, command):
    target = command.get("target")
    config_file = command.get("configFile")
    device_id = command.get("deviceId")
    print(f"处理 start_capture 命令: target={target}")
    await frida_manager.start_capture(sender, target, config_file, device_id)

async def handle_hook_config_event(sender, command):
    configs = command.get("configs", [])
    print(f"处理 hook_config 命令: {len(configs)} 个配置")
    await frida_manager.apply_frida_hooks(sender, configs)

# 事件分发
EVENT_HANDLERS = {
    "start_capture": handle_start_capture_event,
    "hook_config": handle_hook_config_event
}

# 处理客户端命令
async def handle_client_command(sender, message):
    try:
        command = json.loads(message)
        command_type = command.get("type")
        print(f"处理命令类型: {command_type}")
        print(f"消息发送者: {sender}")
        
        if command_type in EVENT_HANDLERS:
            await EVENT_HANDLERS[command_type](sender, command)
        else:
            print(f"未知命令类型: {command_type}")
            
    except json.JSONDecodeError:
        print("无法解析WebSocket消息为JSON")
    except Exception as e:
        print(f"处理WebSocket消息时出错: {e}")
        import traceback
        traceback.print_exc()

# 处理客户端连接
async def handle_client(websocket, path):
    global connected_clients
    
    print(f"客户端已连接: {websocket}")
    connected_clients.add(websocket)    
    try:
        async for message in websocket:
            print(f"收到客户端 {websocket} 的消息: {message}")
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
        print("客户端断开连接处理完成")

# 主函数
async def main():
    global main_loop, frida_manager
    main_loop = asyncio.get_running_loop()
    frida_manager = FridaManager()
    frida_manager.message_callback = WebSocketMessageSender.send_to_all
    async with websockets.serve(handle_client, "localhost", 8080):
        print("WebSocket服务器运行在 localhost:8080")
        await asyncio.Future()

if __name__ == "__main__":
    asyncio.run(main())