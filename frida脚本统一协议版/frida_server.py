import frida
import asyncio
import websockets
import json
import os
import queue

# 全局变量
connected_clients = set()  # 存储前端 WebSocket 连接
device = None
session = None
script = None
current_device_id = "emulator-5554"
current_config = []

# 获取 allenum.js 文件路径
script_dir = os.path.dirname(os.path.realpath(__file__))
allenum_js_path = os.path.join(script_dir, "allenum.js")
project_root = os.path.dirname(os.path.realpath(__file__))
config_dir = os.path.join(project_root, "HOOK配置")

# 用于在Frida线程和WebSocket线程之间传递数据的队列
data_queue = None

# 读取配置文件
def read_config_file(config_filename):
    """读取指定的配置文件并提取hook配置"""
    try:
        # 如果config_filename为空，则使用默认的test.json
        if not config_filename:
            config_filename = "test.json"
            
        config_path = os.path.join(config_dir, config_filename)
        if not os.path.exists(config_path):
            print(f"配置文件不存在: {config_path}")
            return None
            
        with open(config_path, 'r', encoding='utf-8') as f:
            # 直接加载JSON配置文件
            configs = json.load(f)
            print(f"已加载 {len(configs)} 个Hook配置项")
            return configs
    except Exception as e:
        print(f"读取配置文件时出错: {e}")
        return None

# 读取allenum.js文件内容
def read_allenum_js():
    try:
        with open(allenum_js_path, 'r', encoding='utf-8') as f:
            return f.read()
    except Exception as e:
        print(f"读取allenum.js文件时出错: {e}")
        return None

# 生成包含自定义methods_names的Frida脚本
def generate_frida_script_with_config(configs):
    allenum_js_content = read_allenum_js()
    if not allenum_js_content:
        return None

    methods_names_json = json.dumps(configs, ensure_ascii=False, indent=2)
    new_methods_names = f"var methods_names = {methods_names_json};"
    
    result = new_methods_names + "\n" + allenum_js_content
    return result

# Frida消息处理函数
def on_message(message, data):
    global data_queue
    
    try:
        if message['type'] == 'send':
            payload = message.get('payload')
            if isinstance(payload, str):
                try:
                    # 尝试解析JSON字符串
                    payload = json.loads(payload)
                except:
                    # 如果不是JSON，保持原样
                    pass
                    
            # 发送数据到WebSocket服务器
            # 将消息放入队列，由WebSocket线程处理
            data_queue.put({
                "type": "frida_data",
                "data": payload
            })
        elif message['type'] == 'error':
            print(f"[Frida错误] {message}")
    except Exception as e:
        print(f"处理Frida消息时出错: {e}")

# 启动捕获
async def start_capture(target, config_filename=None, device_id=None):
    global device, session, script, current_device_id, current_config
    
    try:
        print(f"开始捕获: {target}")
        
        # 更新设备ID
        if device_id:
            current_device_id = device_id
            
        # 获取设备
        try:
            device = frida.get_device(current_device_id)
            print(f"连接到设备: {current_device_id}")
        except Exception as e:
            print(f"连接设备失败: {e}")
            # 如果无法连接到指定设备，使用本地设备
            try:
                device = frida.get_local_device()
                print("使用本地设备")
            except Exception as e2:
                error_msg = "无法获取设备"
                print(error_msg)
                await send_error_to_clients(error_msg)
                return
        
        # 如果提供了配置文件名，则读取配置
        if config_filename:
            configs = read_config_file(config_filename)
            if configs is not None:  # 明确检查是否为None
                current_config = configs
                print(f"已加载配置: {config_filename}")
            else:
                print("使用默认配置")
        else:
            print("未提供配置文件，使用当前配置")
        
        # 附加到目标进程
        try:
            session = device.attach(target)
            print(f"已附加到进程: {target}")
        except Exception as e:
            print(f"附加进程失败，尝试spawn模式: {e}")
            # 如果附加失败，尝试spawn模式
            try:
                pid = device.spawn([target])
                session = device.attach(pid)
                device.resume(pid)
                print(f"已通过spawn模式启动: {target}")
            except Exception as e2:
                error_msg = "无法启动目标应用"
                print(error_msg)
                await send_error_to_clients(error_msg)
                return
                
        # 生成包含配置的Frida脚本
        script_content = generate_frida_script_with_config(current_config)
        if not script_content:
            script_content = read_allenum_js()  # 回退到原始脚本
            if not script_content:
                print("无法读取Frida脚本内容")
                await send_error_to_clients("无法读取Frida脚本内容")
                return
            
        script = session.create_script(script_content)
        
        # 设置消息处理函数
        script.on('message', on_message)
        
        # 加载脚本
        script.load()
        print("Frida脚本已加载")
        
        # 发送确认消息到前端
        await send_capture_started_to_clients(target, config_filename, device_id)

    except Exception as e:
        error_msg = f"启动捕获失败: {str(e)}"
        print(error_msg)
        await send_error_to_clients(error_msg)

# 应用Frida hooks
async def apply_frida_hooks(configs):
    global device, session, script, current_config
    
    # 更新当前配置
    current_config = configs
    print(f"应用Hook配置，共 {len(configs)} 项")
    
    try:
        # 如果已有脚本，先尝试通过RPC更新配置
        if script:
            try:
                if hasattr(script, 'exports_sync') and hasattr(script.exports_sync, 'update_hook_config'):
                    script.exports_sync.update_hook_config(configs)
                    await send_hooks_applied_to_clients(len(configs))
                    return
                elif hasattr(script, 'exports_sync') and hasattr(script.exports_sync, 'updateHookConfig'):
                    script.exports_sync.updateHookConfig(configs)
                    await send_hooks_applied_to_clients(len(configs))
                    return
            except Exception as e:
                print(f"通过RPC更新配置失败: {e}")
        
        # 如果没有会话，需要先启动捕获
        if not session:
            print("请先启动捕获再应用Hook配置")
            await send_error_to_clients("请先启动捕获再应用Hook配置")
            return
            
        # 生成包含新配置的脚本
        script_content = generate_frida_script_with_config(configs)
        if not script_content:
            script_content = read_allenum_js()  # 回退到原始脚本
            if not script_content:
                print("无法读取Frida脚本内容")
                await send_error_to_clients("无法读取Frida脚本内容")
                return
            
        # 如果已有脚本，先卸载旧脚本
        if script:
            try:
                script.unload()
            except:
                pass
                
        # 创建并加载新脚本
        script = session.create_script(script_content)
        script.on('message', on_message)
        script.load()
        print("Frida脚本已更新并加载")
        
        # 发送确认消息到前端
        await send_hooks_applied_to_clients(len(configs))
        
    except Exception as e:
        error_msg = f"应用Hook配置失败: {str(e)}"
        print(error_msg)
        await send_error_to_clients(error_msg)

# 发送错误消息到所有客户端
async def send_error_to_clients(message):
    error_msg = {
        "type": "error",
        "message": message
    }
    
    clients_to_send = list(connected_clients)
    if clients_to_send:
        message_str = json.dumps(error_msg)
        await asyncio.gather(
            *[client.send(message_str) for client in clients_to_send],
            return_exceptions=True
        )

# 发送捕获开始确认消息到所有客户端
async def send_capture_started_to_clients(target, config_file, device_id):
    msg = {
        "type": "capture_started",
        "target": target,
        "configFile": config_file,
        "deviceId": device_id
    }
    
    clients_to_send = list(connected_clients)
    if clients_to_send:
        message_str = json.dumps(msg)
        await asyncio.gather(
            *[client.send(message_str) for client in clients_to_send],
            return_exceptions=True
        )

# 发送hooks应用确认消息到所有客户端
async def send_hooks_applied_to_clients(config_count):
    msg = {
        "type": "hooks_applied",
        "config_count": config_count
    }
    
    clients_to_send = list(connected_clients)
    if clients_to_send:
        message_str = json.dumps(msg)
        await asyncio.gather(
            *[client.send(message_str) for client in clients_to_send],
            return_exceptions=True
        )

# 处理前端WebSocket连接
async def handle_client(websocket, path):
    global connected_clients
    
    print("客户端已连接")
    connected_clients.add(websocket)
    
    try:
        async for message in websocket:
            await handle_client_command(websocket, message)
    except websockets.exceptions.ConnectionClosed:
        pass
    except Exception as e:
        print(f"处理客户端消息时出错: {e}")
    finally:
        connected_clients.remove(websocket)
        print("客户端已断开连接")

# 处理来自客户端的命令
async def handle_client_command(sender, message):
    global frida_adapter
    
    try:
        command = json.loads(message)
        command_type = command.get("type")
        print(f"处理命令: {command_type}")
        
        # 处理启动捕获命令
        if command_type in ["hook_config", "start_capture"]:
            # 在整合版本中，服务器本身就是适配器，直接处理命令
            if command_type == "start_capture":
                target = command.get("target")
                if not target:
                    await send_error_to_clients("缺少目标应用包名")
                    return
                
                asyncio.create_task(start_capture(target, command.get("configFile"), command.get("deviceId")))
            
            # 处理应用Hook配置命令
            elif command_type == "hook_config":
                configs = command.get("configs")
                if not configs:
                    await send_error_to_clients("缺少Hook配置")
                    return
                    
                asyncio.create_task(apply_frida_hooks(configs))
        
        # 处理Frida适配器注册（在这个整合版本中，服务器本身就是适配器）
        elif command_type == "register_adapter":
            frida_adapter = sender
            print("Frida适配器已注册（服务器本身）")
            
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
        await send_error_to_clients("消息格式错误")
    except Exception as e:
        print(f"处理命令时出错: {e}")
        await send_error_to_clients(f"处理命令时出错: {str(e)}")

# 处理Frida数据队列
async def process_frida_data():
    global data_queue
    while True:
        try:
            # 从队列中获取Frida数据
            data = data_queue.get()
            # 处理Frida数据
            await handle_frida_data(data)
            data_queue.task_done()
        except queue.Empty:
            # 队列为空，等待一会儿再检查
            await asyncio.sleep(0.1)
        except Exception as e:
            print(f"处理Frida数据时出错: {e}")

# 处理Frida数据并广播给前端
async def handle_frida_data(data):
    # 直接转发Frida数据给所有客户端（保持原始格式）
    clients_to_send = list(connected_clients)
    if clients_to_send:
        # 如果data已经是字典并且包含type字段，直接发送
        if isinstance(data, dict) and "type" in data:
            message_str = json.dumps(data, ensure_ascii=False)
        else:
            # 否则包装成标准格式
            frida_data = {
                "type": "frida_data",
                "data": data
            }
            message_str = json.dumps(frida_data, ensure_ascii=False)
            
        await asyncio.gather(
            *[client.send(message_str) for client in clients_to_send],
            return_exceptions=True
        )

# WebSocket服务器主函数
async def start_websocket_server():
    print("正在启动WebSocket服务器...")
    async with websockets.serve(handle_client, "localhost", 8080):
        print("WebSocket服务器运行在 localhost:8080")
        await asyncio.Future()  # 运行直到被中断

# 主函数
async def main():
    global data_queue
    print("Frida服务器启动")
    print(f"allenum.js路径: {allenum_js_path}")
    
    # 使用线程安全的Queue用于Frida回调
    data_queue = queue.Queue()
    
    # 启动WebSocket服务器和Frida数据处理任务
    try:
        await asyncio.gather(
            start_websocket_server(),
            process_frida_data()
        )
    except asyncio.CancelledError:
        print("服务器已关闭")
    except Exception as e:
        print(f"服务器运行出错: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n正在关闭服务器...")
    except Exception as e:
        print(f"服务器启动失败: {e}")
        import traceback
        traceback.print_exc()
