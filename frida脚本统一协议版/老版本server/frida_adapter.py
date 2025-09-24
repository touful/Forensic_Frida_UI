import frida
import asyncio
import websockets
import json
import threading
import sys
import os
import queue
import re

# 获取项目根目录
project_root = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
# 配置文件目录
config_dir = os.path.join(os.path.join(project_root, "frida脚本统一协议版"), "HOOK配置")

# 获取allenum.js文件路径
script_dir = os.path.dirname(os.path.realpath(__file__))
allenum_js_path = os.path.join(script_dir, "allenum.js")

# 全局变量
device = None
session = None
script = None

# 当前设备ID
current_device_id = "emulator-5554"

# WebSocket连接到server.py
websocket_uri = "ws://localhost:8080"
websocket_client = None

# 用于在Frida线程和WebSocket线程之间传递数据的队列
data_queue = queue.Queue()

# 当前配置
current_config = []

# 读取配置文件
def read_config_file(config_filename):
    """读取指定的配置文件并提取hook配置"""
    try:
        if not config_filename:
            config_filename = "test.json"
            
        config_path = os.path.join(config_dir, config_filename)
        if not os.path.exists(config_path):
            print(f"配置文件不存在: {config_path}")
            return None
            
        with open(config_path, 'r', encoding='utf-8') as f:
            configs = json.load(f)
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
    global websocket_client
    
    try:
        if message['type'] == 'send':
            payload = message.get('payload')
            if isinstance(payload, str):
                try:
                    payload = json.loads(payload)
                except:
                    pass
                    
            # 发送数据到WebSocket服务器
            if websocket_client and not websocket_client.closed:
                # 将消息放入队列，由WebSocket线程处理
                data_queue.put({
                    "type": "frida_data",
                    "payload": payload
                })
        elif message['type'] == 'error':
            print(f"[Frida错误] {message}")
    except Exception as e:
        print(f"处理Frida消息时出错: {e}")

# 启动捕获
async def start_capture(target, config_filename=None, device_id=None):
    global device, session, script, current_device_id, current_config
    
    try:
        print(f"开始捕获目标: {target}")
        
        if device_id:
            current_device_id = device_id
        
        try:
            device = frida.get_device(current_device_id)
            print(f"成功连接到设备: {current_device_id}")
        except Exception as e:
            print(f"连接到设备 {current_device_id} 失败: {e}")
            try:
                device = frida.get_local_device()
                print("使用本地设备")
            except Exception as e2:
                error_msg = f"无法获取任何设备: {str(e2)}"
                print(error_msg)
                if websocket_client and not websocket_client.closed:
                    await websocket_client.send(json.dumps({
                        "type": "error",
                        "message": error_msg
                    }))
                return
        
        if config_filename:
            configs = read_config_file(config_filename)
            if configs is not None:
                current_config = configs
            else:
                print("无法加载配置文件，使用默认配置")
        
        try:
            session = device.attach(target)
            print(f"成功附加到进程: {target}")
        except Exception as e:
            print(f"附加到进程失败: {e}")
            try:
                print(f"尝试spawn模式启动: {target}")
                pid = device.spawn([target])
                session = device.attach(pid)
                device.resume(pid)
                print(f"Spawn模式启动成功: {target}")
            except Exception as e2:
                error_msg = f"Spawn模式启动失败: {str(e2)}"
                print(error_msg)
                if websocket_client and not websocket_client.closed:
                    await websocket_client.send(json.dumps({
                        "type": "error",
                        "message": error_msg
                    }))
                return
                
        script_content = generate_frida_script_with_config(current_config)
        if not script_content:
            script_content = read_allenum_js()
            if not script_content:
                print("无法读取Frida脚本内容")
                return
            
        script = session.create_script(script_content)
        script.on('message', on_message)
        script.load()
        print("Frida脚本加载完成")
        
        try:
            if hasattr(script, 'exports_sync'):
                if hasattr(script.exports_sync, 'set_package_name'):
                    script.exports_sync.set_package_name(target)
                elif hasattr(script.exports_sync, 'setPackageName'):
                    script.exports_sync.setPackageName(target)
                else:
                    print("Frida脚本中未找到 'set_package_name' 或 'setPackageName' 方法")
            elif hasattr(script, 'exports'):
                if hasattr(script.exports, 'set_package_name'):
                    script.exports.set_package_name(target)
                elif hasattr(script.exports, 'setPackageName'):
                    script.exports.setPackageName(target)
                else:
                    print("Frida脚本中未找到 'set_package_name' 或 'setPackageName' 方法")
            else:
                print("脚本没有exports或exports_sync属性")
        except Exception as e:
            print(f"调用包名设置方法失败: {e}")

        if websocket_client and not websocket_client.closed:
            try:
                await websocket_client.send(json.dumps({
                    "type": "capture_started",
                    "target": target,
                    "configFile": config_filename,
                    "deviceId": device_id
                }))
                print("已发送捕获开始确认消息")
            except Exception as e:
                print(f"发送捕获开始确认消息失败: {e}")

    except Exception as e:
        error_msg = f"启动捕获时出错: {str(e)}"
        print(error_msg)
        if websocket_client and not websocket_client.closed:
            await websocket_client.send(json.dumps({
                "type": "error",
                "message": error_msg
            }))

# 应用Frida hooks
async def apply_frida_hooks(configs):
    global device, session, script, current_config
    
    current_config = configs
    print(f"应用Frida hooks，配置数量: {len(configs)}")
    
    try:
        if script:
            try:
                if hasattr(script, 'exports_sync') and hasattr(script.exports_sync, 'update_hook_config'):
                    result = script.exports_sync.update_hook_config(configs)
                elif hasattr(script, 'exports') and hasattr(script.exports, 'update_hook_config'):
                    result = script.exports.update_hook_config(configs)
                elif hasattr(script, 'exports_sync') and hasattr(script.exports_sync, 'updateHookConfig'):
                    result = script.exports_sync.updateHookConfig(configs)
                elif hasattr(script, 'exports') and hasattr(script.exports, 'updateHookConfig'):
                    result = script.exports.updateHookConfig(configs)
                else:
                    print("Frida脚本中未找到 'update_hook_config' 方法")
                    return
                
                if websocket_client and not websocket_client.closed:
                    await websocket_client.send(json.dumps({
                        "type": "hooks_applied",
                        "config_count": len(configs)
                    }))
                return
            except Exception as e:
                print(f"通过RPC更新配置失败: {e}")
        
        if not session:
            print("请先启动捕获再应用Hook配置")
            if websocket_client and not websocket_client.closed:
                await websocket_client.send(json.dumps({
                    "type": "error",
                    "message": "请先启动捕获再应用Hook配置"
                }))
            return
            
        script_content = generate_frida_script_with_config(configs)
        if not script_content:
            script_content = read_allenum_js()
            if not script_content:
                print("无法读取Frida脚本内容")
                if websocket_client and not websocket_client.closed:
                    await websocket_client.send(json.dumps({
                        "type": "error",
                        "message": "无法读取Frida脚本内容"
                    }))
                return
            
        script = session.create_script(script_content)
        script.on('message', on_message)
        script.load()
        
        try:
            if hasattr(script, 'exports_sync') and hasattr(script.exports_sync, 'updateHookConfig'):
                script.exports_sync.updateHookConfig(configs)
            elif hasattr(script, 'exports_sync') and hasattr(script.exports_sync, 'update_hook_config'):
                script.exports_sync.update_hook_config(configs)
            elif hasattr(script, 'exports') and hasattr(script.exports, 'updateHookConfig'):
                script.exports.updateHookConfig(configs)
            elif hasattr(script, 'exports') and hasattr(script.exports, 'update_hook_config'):
                script.exports.update_hook_config(configs)
            else:
                print("Frida脚本中未找到 'updateHookConfig' 方法")
        except Exception as e:
            print(f"调用更新Hook配置方法失败: {e}")

        if websocket_client and not websocket_client.closed:
            await websocket_client.send(json.dumps({
                "type": "hooks_applied",
                "config_count": len(configs)
            }))
            
    except Exception as e:
        error_msg = f"应用Frida hooks时出错: {str(e)}"
        print(error_msg)
        if websocket_client and not websocket_client.closed:
            await websocket_client.send(json.dumps({
                "type": "error",
                "message": error_msg
            }))

# WebSocket消息处理
async def handle_websocket_message(message):
    global device, session, script
    
    try:
        command = json.loads(message)
        command_type = command.get("type")
        
        if command_type == "start_capture":
            target = command.get("target")
            config_file = command.get("configFile")
            device_id = command.get("deviceId")
            print(f"处理 start_capture 命令: target={target}")
            await start_capture(target, config_file, device_id)
            
        elif command_type == "hook_config":
            configs = command.get("configs", [])
            print(f"处理 hook_config 命令: {len(configs)} 个配置")
            await apply_frida_hooks(configs)
            
        elif command_type == "register_adapter":
            print("收到注册适配器确认消息")
            
        else:
            print(f"未知命令类型: {command_type}")
            
    except json.JSONDecodeError:
        print("无法解析WebSocket消息为JSON")
    except Exception as e:
        print(f"处理WebSocket消息时出错: {e}")

# WebSocket客户端循环
async def websocket_client_handler():
    global websocket_client
    
    try:
        print("尝试连接到WebSocket服务器...")
        async with websockets.connect(websocket_uri) as websocket:
            websocket_client = websocket
            print("已连接到WebSocket服务器")
            
            register_msg = json.dumps({
                "type": "register_adapter"
            })
            await websocket.send(register_msg)
            print("已发送注册消息")
            
            send_task = asyncio.create_task(process_data_queue())
            
            print("开始监听WebSocket消息...")
            async for message in websocket:
                await handle_websocket_message(message)
                
    except Exception as e:
        print(f"WebSocket客户端错误: {e}")
        websocket_client = None

# 处理队列中的数据并发送到WebSocket
async def process_data_queue():
    while True:
        try:
            # 从队列中获取数据
            data = data_queue.get(timeout=1)
            # 发送数据到WebSocket
            await send_data_to_websocket(data)
            data_queue.task_done()
        except queue.Empty:
            # 队列为空，继续循环
            await asyncio.sleep(0.1)
        except Exception as e:
            print(f"处理队列数据时出错: {e}")

# 发送数据到WebSocket服务器
async def send_data_to_websocket(data):
    global websocket_client
    
    if websocket_client and not websocket_client.closed:
        try:
            await websocket_client.send(json.dumps(data))
        except Exception as e:
            print(f"发送数据到WebSocket时出错: {e}")

# 启动WebSocket客户端
def start_websocket_client():
    print("启动WebSocket客户端...")
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(websocket_client_handler())

if __name__ == "__main__":
    # 启动WebSocket客户端
    start_websocket_client()