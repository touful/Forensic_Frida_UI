
// 需要hook的方法名列表（将通过Python动态传递）
/**
 * 格式化时间戳
 */
function formatTimestamp() {
    const now = new Date();
    return `${now.getFullYear()}-${(now.getMonth()+1).toString().padStart(2, '0')}-${now.getDate().toString().padStart(2, '0')} ` +
           `${now.getHours().toString().padStart(2, '0')}:${now.getMinutes().toString().padStart(2, '0')}:${now.getSeconds().toString().padStart(2, '0')}.${now.getMilliseconds().toString().padStart(3, '0')}`;
}

// 自定义日志函数，添加颜色和格式
function log(type, message) {
    const timestamp = formatTimestamp();
    let prefix = '';
    let color = '';
    
    switch(type) {
        case 'info':
            prefix = '[INFO]';
            color = '\x1b[36m'; // 青色
            break;
        case 'hook':
            prefix = '[HOOK]';
            color = '\x1b[32m'; // 绿色
            break;
        case 'data':
            prefix = '[DATA]';
            color = '\x1b[33m'; // 黄色
            break;
        case 'error':
            prefix = '[ERROR]';
            color = '\x1b[31m'; // 红色
            break;
        case 'rpc':
            prefix = '[RPC]';
            color = '\x1b[35m'; // 紫色
            break;
        case 'debug':
            prefix = '[DEBUG]';
            color = '\x1b[33m'; // 黄色
            break;
        default:
            prefix = `[${type.toUpperCase()}]`;
            color = '\x1b[0m'; // 默认颜色
    }
    
    const reset = '\x1b[0m';
    console.log(`${color}${timestamp} ${prefix} ${message}${reset}`);
}
/**
 * 枚举一个 JavaScript 类的所有静态属性、原型属性和方法
 * @param {Function} cls - 传入的类（构造函数）
 * @param {Object} options - 配置选项
 * @param {boolean} [options.includeInherited=false] - 是否包含继承的属性
 * @param {boolean} [options.includeSymbols=false] - 是否包含 Symbol 属性
 * @param {boolean} [options.includeNonEnumerable=false] - 是否包含不可枚举属性
 * @returns {Object} 包含 static, prototype 的结构化信息
 */
function enumerateClass(cls, options = {}) {
  const {
    includeInherited = false,
    includeSymbols = false,
    includeNonEnumerable = false
  } = options;

  const result = {
    static: {},
    prototype: {}
  };

  // 获取属性描述符的辅助函数
  const getDescriptor = (obj, key) => {
    const descriptor = Object.getOwnPropertyDescriptor(obj, key);
    if (!descriptor) return null;
    const info = {
      type: typeof obj[key],
      enumerable: descriptor.enumerable,
      configurable: descriptor.configurable,
      writable: descriptor.writable !== undefined ? descriptor.writable : 'N/A',
      value: typeof obj[key] === 'function' ? '[Function]' : obj[key]
    };
    return info;
  };

  // 枚举对象属性的通用函数
  const enumerateProperties = (obj, target) => {
    let keys = includeSymbols ? Reflect.ownKeys(obj) : Object.getOwnPropertyNames(obj);
    for (let key of keys) {
      // 过滤内置 Symbol（如 Symbol(Symbol.iterator) 等），除非是自定义 Symbol
      if (typeof key === 'symbol' && !includeSymbols) continue;

      // 跳过构造函数（避免冗余）
      if (key === 'constructor' && obj === cls.prototype) continue;

      const descriptor = getDescriptor(obj, key);
      if (!descriptor) continue;

      // 跳过不可枚举属性（除非指定包含）
      if (!descriptor.enumerable && !includeNonEnumerable) continue;

      target[key] = descriptor;
    }
  };

  // 枚举静态属性（类本身）
  enumerateProperties(cls, result.static);

  // 枚举原型属性（实例方法/属性）
  enumerateProperties(cls.prototype, result.prototype);

  // 如果需要包含继承属性
  if (includeInherited) {
    let proto = Object.getPrototypeOf(cls.prototype);
    while (proto && proto !== Object.prototype) {
      enumerateProperties(proto, result.prototype);
      proto = Object.getPrototypeOf(proto);
    }

    // 继承的静态属性（从 Function 或其他父类）
    let staticProto = Object.getPrototypeOf(cls);
    while (staticProto && staticProto !== Function.prototype) {
      enumerateProperties(staticProto, result.static);
      staticProto = Object.getPrototypeOf(staticProto);
    }
  }

  return result;
}

/**
 * 枚举Java对象的属性和方法
 * @param {Object} obj - Java对象
 * @returns {Object} 包含类名、字段和方法的结构化信息
 */
function enumerateJavaObject(obj) {
    if (!obj || !obj.$className) {
        console.warn("Not a valid Java object:", obj);
        return null;
    }

    const result = {
        $className: obj.$className,
        fields: {},
        methods: []
    };

    try {
        // 辅助函数：尝试将字节数组解码为字符串
        function tryDecodeString(byteArray) {
            try {
                return new TextDecoder('utf-8').decode(new Uint8Array(byteArray));
            } catch (e) {
                return null;
            }
        }

        // 基本类型映射
        const typeMap = {
            '[B': 'byte',
            '[I': 'int',
            '[S': 'short',
            '[J': 'long',
            '[F': 'float',
            '[D': 'double',
            '[C': 'char',
            '[Z': 'boolean'
        };

        // 获取 Java class
        const klass = Java.use(obj.$className);

        // ================== 枚举所有字段（包括父类） ==================
        let currentClass = klass.class;
        while (currentClass && !currentClass.equals(Java.use('java.lang.Object').class)) {
            // 获取所有 declared fields（包括 private）
            const fields = currentClass.getDeclaredFields();
            for (let i = 0; i < fields.length; i++) {
                const field = fields[i];
                const fieldName = field.getName();
                const fieldType = field.getType().getName();

                // 设置可访问（突破 private 限制）
                field.setAccessible(true);

                try {
                    const value = field.get(obj);
                    let processedValue;
                    // 处理数组类型
                    if (fieldType.startsWith('[')) {
                        const baseType = typeMap[fieldType];
                        if (baseType) {
                            try {
                                // 使用Java.array可靠获取数组内容
                                const jsArray = Java.array(baseType, value);
                                
                                if (baseType === 'byte') {
                                    const hex = Array.from(jsArray).map(b => ('0' + (b & 0xFF).toString(16)).slice(-2)).join('');
                                    processedValue = {
                                        type: 'byte[]',
                                        len: jsArray.length,
                                        hex: hex,
                                        str: tryDecodeString(jsArray)
                                    };
                                } else if (baseType === 'long') {
                                    // 长整型需转字符串避免精度丢失
                                    const values = jsArray.map(x => x.toString());
                                    processedValue = {
                                        type: 'long[]',
                                        len: jsArray.length,
                                        vals: values
                                    };
                                } else {
                                    processedValue = {
                                        type: fieldType.replace('[', '') + '[]',
                                        len: jsArray.length,
                                        vals: jsArray
                                    };
                                }
                            } catch (e) {
                                processedValue = {
                                    type: fieldType,
                                    err: "Array conversion failed: " + e.message,
                                    acc: false
                                };
                            }
                        } else {
                            processedValue = value ? value.toString() : null;
                        }
                    } else {
                        processedValue = value ? value.toString() : null;
                    }
                    result.fields[fieldName] = {
                        type: fieldType,
                        val: processedValue,
                        acc: true
                    };
                } catch (e) {
                    result.fields[fieldName] = {
                        type: fieldType,
                        err: "Cannot access field: " + e.message,
                        acc: false
                    };
                }
            }

            // 继续遍历父类
            currentClass = currentClass.getSuperclass();
        }

        // ================== 枚举所有方法（包括父类） ==================
        currentClass = klass.class;
        while (currentClass && !currentClass.equals(Java.use('java.lang.Object').class)) {
            const methods = currentClass.getDeclaredMethods();
            for (let i = 0; i < methods.length; i++) {
                const method = methods[i];
                const methodName = method.getName();
                const paramTypes = method.getParameterTypes();
                const returnType = method.getReturnType().getName();

                const paramNames = [];
                for (let j = 0; j < paramTypes.length; j++) {
                    paramNames.push(paramTypes[j].getName());
                }

                result.methods.push({
                    name: methodName,
                    ret: returnType,
                    params: paramNames,
                    acc: method.isAccessible()
                });
            }

            currentClass = currentClass.getSuperclass();
        }

    } catch (e) {
        console.error("Error enumerating Java object:", e);
        result.err = e.toString();
    }

    return result;
}

function toString_touful(obj) {
    if (obj == undefined || obj == null) {
        return "null";
    }
    
    // 检查是否为Java对象
    if (obj.$className) {
        try {
            const enumResult = enumerateJavaObject(obj);
            return JSON.stringify(enumResult);
        } catch (e) {
            return `[Java Object: ${obj.$className}] (枚举失败: ${e.message})`;
        }
    }
    
    try {
        // 尝试获取类名
        const className = obj.getClass ? obj.getClass().getName() : '';
        
        if (obj.toString && obj.toString() !== "[object Object]") {
            return `${obj.toString()}${className ? ` (${className})` : ''}`;
        } else {
            // 对于复杂对象，尝试JSON序列化
            try {
                return JSON.stringify(enumerateClass(obj));
            } catch (e) {
                return `[Object]${className ? ` (${className})` : ''}`;
            }
        }
    } catch (e) {
        return "[无法转换的对象]";
    }
}

/**
 * 检查参数是否匹配避免条件
 * @param args 函数调用的参数数组
 * @param avoidArgs 需要避免的参数值数组
 * @returns {boolean} 如果匹配避免条件返回true，否则返回false
 */
function shouldAvoidArgs(args, avoidArgs) {
    if (avoidArgs.length > 0) {
        for (var i = 0; i < args.length; i++) {
            var argStr = toString_touful(args[i]);
            for (var j = 0; j < avoidArgs.length; j++) {
                var avoidArg = avoidArgs[j];
                
                // 检查front匹配（前缀匹配）
                if (avoidArg.front && avoidArg.front.length > 0) {
                    for (var k = 0; k < avoidArg.front.length; k++) {
                        if (argStr.startsWith(avoidArg.front[k])) {
                            return true;
                        }
                    }
                }
                
                // 检查back匹配（后缀匹配）
                if (avoidArg.back && avoidArg.back.length > 0) {
                    for (var k = 0; k < avoidArg.back.length; k++) {
                        if (argStr.endsWith(avoidArg.back[k])) {
                            return true;
                        }
                    }
                }
                
                // 检查matchall匹配（完整匹配）
                if (avoidArg.matchall && avoidArg.matchall.length > 0) {
                    for (var k = 0; k < avoidArg.matchall.length; k++) {
                        if (argStr === avoidArg.matchall[k]) {
                            return true;
                        }
                    }
                }
            }
        }
    }
    return false;
}

/**
 * 检查返回值是否匹配避免条件
 * @param result 函数调用的返回值
 * @param avoidReturns 需要避免的返回值数组
 * @returns {boolean} 如果匹配避免条件返回true，否则返回false
 */
function shouldAvoidReturns(result, avoidReturns) {
    if (avoidReturns.length > 0) {
        var resultStr = toString_touful(result);
        for (var i = 0; i < avoidReturns.length; i++) {
            var avoidReturn = avoidReturns[i];
            
            // 检查front匹配（前缀匹配）
            if (avoidReturn.front && avoidReturn.front.length > 0) {
                for (var k = 0; k < avoidReturn.front.length; k++) {
                    if (resultStr.startsWith(avoidReturn.front[k])) {
                        return true;
                    }
                }
            }
            
            // 检查back匹配（后缀匹配）
            if (avoidReturn.back && avoidReturn.back.length > 0) {
                for (var k = 0; k < avoidReturn.back.length; k++) {
                    if (resultStr.endsWith(avoidReturn.back[k])) {
                        return true;
                    }
                }
            }
            
            // 检查matchall匹配（完整匹配）
            if (avoidReturn.matchall && avoidReturn.matchall.length > 0) {
                for (var k = 0; k < avoidReturn.matchall.length; k++) {
                    if (resultStr === avoidReturn.matchall[k]) {
                        return true;
                    }
                }
            }
        }
    }
    return false;
}
/**
 * 枚举指定类的所有方法并进行hook
 * @param classname 类名，如：java.lang.String
 * @param methods_names 需要hook的方法配置数组
 */
function class_enum(classname, methods_names){
    /*
    枚举某类的所有方法,classname参数为类名，如：java.lang.String
    */
    log('info', `正在枚举类: ${classname}`);
    
    // 过滤出当前类需要hook的方法
    var targetMethods = [];
    for (var i = 0; i < methods_names.length; i++) {
        if (methods_names[i].class === classname) {
            targetMethods.push(methods_names[i]);
        }
    }
    
    if (targetMethods.length === 0) {
        log('info', `类 ${classname} 没有需要hook的方法`);
        return;
    }
    
    log('info', `类 ${classname} 找到 ${targetMethods.length} 个需要hook的方法`);
    
    Java.perform(function() {
        // 获取类的所有方法
        var clazz = Java.use(classname);
        var methods = clazz.class.getDeclaredMethods();
        
        log('info', `类 ${classname} 共有 ${methods.length} 个声明方法`);
        
        // 遍历所有方法
        for (var i = 0; i < methods.length; i++) {
            var methodName = methods[i].getName();
            
            // 检查是否是需要hook的方法
            var targetMethod = null;
            for (var j = 0; j < targetMethods.length; j++) {
                if (targetMethods[j].method === methodName) {
                    targetMethod = targetMethods[j];
                    break;
                }
            }
            
            // 如果是需要hook的方法
            if (targetMethod) {
                log('hook', `正在Hook方法: ${classname}.${methodName}`);
                try {
                    // 获取方法的所有重载
                    var overloads = clazz[methodName].overloads;
                    // 统一处理重载方法（包括没有重载的方法）
                    if (overloads && overloads.length > 0) {
                        log('hook', `方法 ${classname}.${methodName} 有 ${overloads.length} 个重载`);
                        for (var k = 0; k < overloads.length; k++) {
                            (function(overload, className, methodName, avoidArgs, avoidReturns) {
                                overload.implementation = function () {
                                    // 收集所有参数
                                    var args = [];
                                    for (var j = 0; j < arguments.length; j++) {
                                        args.push(toString_touful(arguments[j]));
                                    }
                                    
                                    // 调用原始方法并获取返回值
                                    var result = overload.apply(this, arguments);
                                    
                                    // 检查是否匹配避免的参数和返回值
                                    var shouldAvoid = shouldAvoidArgs(args, avoidArgs) || shouldAvoidReturns(result, avoidReturns);
                                    
                                    // 如果不匹配避免条件，则发送数据
                                    if (!shouldAvoid) {
                                        // 构造JSON对象
                                        var jsonObj = {
                                            "method": className + "." + methodName,
                                            "args": args,
                                            "returns": toString_touful(result)
                                        };
                                        
                                        // 格式化输出到控制台
                                        const argStr = args.length > 0 ? `\n    参数: [${args.join(', ')}]` : '';
                                        const resultStr = result !== undefined ? `\n    返回值: ${toString_touful(result)}` : '';
                                        log('data', `调用方法: ${className}.${methodName}${argStr}${resultStr}`);
                                        
                                        // 使用send方法发送JSON数据
                                        send(jsonObj);
                                    }
                                    return result;
                                };
                            })(overloads[k], classname, methodName, targetMethod.avoid_args, targetMethod.avoid_returns);
                        }
                    }
                } catch (error) {
                    log('error', `Hook方法 ${classname}.${methodName} 时出错: ${error.message}`);
                }
            }
        }
    });
}

// RPC导出函数，用于动态更新hook配置
rpc.exports = {
    updateHookConfig: function(config) {
        log('rpc', `收到更新hook配置请求，共 ${config.length} 个配置项`);
        methods_names = config;
        // 重新执行main函数以应用新的配置
        main();
        return "Hook配置已更新";
    }
};

/**
 * 主函数，程序入口
 */
function main(){
    // 清理之前的hook
    Java.perform(function() {
        log('info', "应用新的Hook配置");
        
        // 遍历所有需要hook的类和方法
        var processedClasses = [];
        for (var i = 0; i < methods_names.length; i++) {
            var item = methods_names[i];
            // 避免重复处理同一个类
            if (processedClasses.indexOf(item.class) === -1) {
                processedClasses.push(item.class);
                class_enum(item.class, methods_names);
            }
        }
        
        if (processedClasses.length > 0) {
            log('info', `已成功Hook ${processedClasses.length} 个类`);
        } else {
            log('info', "未找到需要Hook的类");
        }
    });
}

// 初始执行
log('info', "Frida脚本已加载，开始执行main函数");
main();