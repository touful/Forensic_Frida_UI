import frida
import os
import json


class FridaManager:
    def __init__(self, device_id="09221JEC204223"):
        self.device_id = device_id
        self.device = None
        self.session = None
        self.script = None
        self.current_config = []
        
        # 项目根目录
        self.project_root = os.path.dirname(os.path.realpath(__file__))
        # 配置文件目录
        self.config_dir = os.path.join(self.project_root, "HOOK配置")

    # 读取配置文件
    def read_config_file(self, config_filename):
        """读取指定的配置文件并提取hook配置"""
        try:
            if not config_filename:
                config_filename = "test.json"
                
            config_path = os.path.join(self.config_dir, config_filename)
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
    def read_allenum_js(self):
        try:
            allenum_js_path = os.path.join(self.project_root, "allenum.js")
            with open(allenum_js_path, 'r', encoding='utf-8') as f:
                return f.read()
        except Exception as e:
            print(f"读取allenum.js文件时出错: {e}")
            return None

    # 生成包含自定义methods_names的Frida脚本
    def generate_frida_script_with_config(self, configs):
        # 读取原始allenum.js内容
        allenum_js_content = self.read_allenum_js()
        if not allenum_js_content:
            return None

        # 生成methods_names数组
        methods_names_json = json.dumps(configs, ensure_ascii=False, indent=4)
        
        # 替换原始脚本中的methods_names定义
        script_lines = allenum_js_content.split('\n')
        new_script_lines = []
        
        methods_names_found = False
        skip_lines = False
        
        for line in script_lines:
            # 检查是否是methods_names定义的开始
            if 'var methods_names=' in line or 'var methods_names =' in line:
                methods_names_found = True
                skip_lines = True
                # 添加新的methods_names定义
                new_script_lines.append(f"var methods_names = {methods_names_json};")
                continue
                
            # 检查是否是methods_names定义的结束
            if skip_lines and line.strip() and not line.strip().startswith('//') and not line.strip().startswith('['):
                skip_lines = False
            
            # 如果不在跳过模式下，则添加原始行
            if not skip_lines:
                new_script_lines.append(line)
        
        # 如果没有找到methods_names定义，则在文件开头添加
        if not methods_names_found:
            new_script_lines.insert(0, f"var methods_names = {methods_names_json};\n")
            
        return '\n'.join(new_script_lines)

    # Frida消息处理函数
    def on_message(self, message, data):
        try:
            if message['type'] == 'send':
                payload = message.get('payload')
                if isinstance(payload, str):
                    try:
                        payload = json.loads(payload)
                    except:
                        pass
                        
                # 直接发送数据到所有连接的前端客户端
                frida_data = {
                    "type": "frida_data",
                    "payload": payload
                }
                # 使用回调函数发送消息
                if self.message_callback:
                    self.message_callback(frida_data)
                else:
                    print("未设置消息回调函数")
            elif message['type'] == 'error':
                print(f"[Frida错误] {message}")
        except Exception as e:
            print(f"处理Frida消息时出错: {e}")
        return None

    # 启动捕获
    async def start_capture(self, sender, target, config_filename=None, device_id=None):
        try:
            print(f"开始捕获目标: {target}")
            
            if device_id:
                self.device_id = device_id
            
            try:
                self.device = frida.get_device(self.device_id)
                print(f"成功连接到设备: {self.device_id}")
            except Exception as e:
                print(f"连接到设备 {self.device_id} 失败: {e}")
                try:
                    self.device = frida.get_local_device()
                    print("使用本地设备")
                except Exception as e2:
                    error_msg = f"无法获取任何设备: {str(e2)}"
                    print(error_msg)
                    await sender.send(json.dumps({
                        "type": "error",
                        "message": error_msg
                    }))
                    return
            
            if config_filename:
                configs = self.read_config_file(config_filename)
                if configs is not None:
                    self.current_config = configs
                else:
                    print("无法加载配置文件，使用默认配置")
            
            try:
                self.session = self.device.attach(target)
                print(f"成功附加到进程: {target}")
            except Exception as e:
                print(f"附加到进程失败: {e}")
                try:
                    print(f"尝试spawn模式启动: {target}")
                    pid = self.device.spawn([target])
                    self.session = self.device.attach(pid)
                    self.device.resume(pid)
                    print(f"Spawn模式启动成功: {target}")
                except Exception as e2:
                    error_msg = f"Spawn模式启动失败: {str(e2)}"
                    print(error_msg)
                    await sender.send(json.dumps({
                        "type": "error",
                        "message": error_msg
                    }))
                    return
                    
            script_content = self.generate_frida_script_with_config(self.current_config)
            if not script_content:
                script_content = self.read_allenum_js()
                if not script_content:
                    print("无法读取Frida脚本内容")
                    await sender.send(json.dumps({
                        "type": "error",
                        "message": "无法读取Frida脚本内容"
                    }))
                    return
                
            self.script = self.session.create_script(script_content)
            self.script.on('message', self.on_message)
            self.script.load()
            print("Frida脚本加载完成")
            

            await sender.send(json.dumps({
                "type": "capture_started",
                "target": target,
                "configFile": config_filename,
                "deviceId": device_id
            }))
            print("已发送捕获开始确认消息")

        except Exception as e:
            error_msg = f"启动捕获时出错: {str(e)}"
            print(error_msg)
            await sender.send(json.dumps({
                "type": "error",
                "message": error_msg
            }))

    # 应用Frida hooks
    async def apply_frida_hooks(self, sender, configs):
        self.current_config = configs
        print(f"应用Frida hooks，配置数量: {len(configs)}")
        
        try:
            if self.script:
                try:
                    if hasattr(self.script, 'exports_sync') and hasattr(self.script.exports_sync, 'update_hook_config'):
                        result = self.script.exports_sync.update_hook_config(configs)
                    elif hasattr(self.script, 'exports') and hasattr(self.script.exports, 'update_hook_config'):
                        result = self.script.exports.update_hook_config(configs)
                    elif hasattr(self.script, 'exports_sync') and hasattr(self.script.exports_sync, 'updateHookConfig'):
                        result = self.script.exports_sync.updateHookConfig(configs)
                    elif hasattr(self.script, 'exports') and hasattr(self.script.exports, 'updateHookConfig'):
                        result = self.script.exports.updateHookConfig(configs)
                    else:
                        print("Frida脚本中未找到 'update_hook_config' 方法")
                        await sender.send(json.dumps({
                            "type": "error",
                            "message": "Frida脚本中未找到 'update_hook_config' 方法"
                        }))
                        return
                    
                    await sender.send(json.dumps({
                        "type": "hooks_applied",
                        "config_count": len(configs)
                    }))
                    return
                except Exception as e:
                    print(f"通过RPC更新配置失败: {e}")
            
            if not self.session:
                print("请先启动捕获再应用Hook配置")
                await sender.send(json.dumps({
                    "type": "error",
                    "message": "请先启动捕获再应用Hook配置"
                }))
                return
                
            script_content = self.generate_frida_script_with_config(configs)
            if not script_content:
                script_content = self.read_allenum_js()
                if not script_content:
                    print("无法读取Frida脚本内容")
                    await sender.send(json.dumps({
                        "type": "error",
                        "message": "无法读取Frida脚本内容"
                    }))
                    return
                
            self.script = self.session.create_script(script_content)
            self.script.on('message', self.on_message)
            self.script.load()
            
            try:
                if hasattr(self.script, 'exports_sync') and hasattr(self.script.exports_sync, 'updateHookConfig'):
                    self.script.exports_sync.updateHookConfig(configs)
                elif hasattr(self.script, 'exports_sync') and hasattr(self.script.exports_sync, 'update_hook_config'):
                    self.script.exports_sync.update_hook_config(configs)
                elif hasattr(self.script, 'exports') and hasattr(self.script.exports, 'updateHookConfig'):
                    self.script.exports.updateHookConfig(configs)
                elif hasattr(self.script, 'exports') and hasattr(self.script.exports, 'update_hook_config'):
                    self.script.exports.update_hook_config(configs)
                else:
                    print("Frida脚本中未找到 'updateHookConfig' 方法")
            except Exception as e:
                print(f"调用更新Hook配置方法失败: {e}")

            await sender.send(json.dumps({
                "type": "hooks_applied",
                "config_count": len(configs)
            }))
                
        except Exception as e:
            error_msg = f"应用Frida hooks时出错: {str(e)}"
            print(error_msg)
            await sender.send(json.dumps({
                "type": "error",
                "message": error_msg
            }))