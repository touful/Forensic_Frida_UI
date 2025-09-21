// 目标应用包名
var baoming="com.example.testoffridalab"
// 需要hook的方法名列表（将通过Python动态传递）

/**
 * 检查参数是否匹配避免条件
 * @param args 函数调用的参数数组
 * @param avoidArgs 需要避免的参数值数组
 * @returns {boolean} 如果匹配避免条件返回true，否则返回false
 */
function shouldAvoidArgs(args, avoidArgs) {
    if (avoidArgs.length > 0) {
        for (var i = 0; i < args.length; i++) {
            var argStr = args[i].toString();
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
        var resultStr = result.toString();
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
 * 枚举指定包名下的所有类
 */
function start(){
    //使用Java.perform确保在Java线程中执行
    Java.perform(function(){
        // 同步获取所有已加载的类
        var classz = Java.enumerateLoadedClassesSync();
        for(var i=0;i<classz.length;i++){
            // 筛选出包含指定包名的类
            if (classz[i].indexOf(baoming) != -1){
                console.log(classz[i]);
            }
        }
    });
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
    console.log("枚举"+classname+"的所有方法");
    
    // 过滤出当前类需要hook的方法
    var targetMethods = [];
    for (var i = 0; i < methods_names.length; i++) {
        if (methods_names[i].class === classname) {
            targetMethods.push(methods_names[i]);
        }
    }
    
    if (targetMethods.length === 0) {
        console.log("没有需要hook的方法在类"+classname);
        return;
    }
    
    Java.perform(function() {
        // 获取类的所有方法
        var clazz = Java.use(classname);
        var methods = clazz.class.getDeclaredMethods();
        
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
                console.log("Hooking method => ", classname, methodName);
                try {
                    // 获取方法的所有重载
                    var overloads = clazz[methodName].overloads;
                    // 统一处理重载方法（包括没有重载的方法）
                    if (overloads && overloads.length > 0) {
                        for (var k = 0; k < overloads.length; k++) {
                            (function(overload, className, methodName, avoidArgs, avoidReturns) {
                                overload.implementation = function () {
                                    // 收集所有参数
                                    var args = [];
                                    for (var j = 0; j < arguments.length; j++) {
                                        args.push(arguments[j].toString());
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
                                            "returns": result.toString()
                                        };
                                        
                                        // 使用send方法发送JSON数据
                                        send(jsonObj);
                                    }
                                    return result;
                                };
                            })(overloads[k], classname, methodName, targetMethod.avoid_args, targetMethod.avoid_returns);
                        }
                    }
                } catch (error) {
                    console.log("Hook方法时出错", classname, methodName, error);
                }
            }
        }
    });
}

// RPC导出函数，用于动态更新hook配置
rpc.exports = {
    updateHookConfig: function(config) {
        console.log("更新hook配置:", JSON.stringify(config));
        methods_names = config;
        // 重新执行main函数以应用新的配置
        main();
        return "Hook配置已更新";
    },
    setPackageName: function(packageName) {
        console.log("设置包名:", packageName);
        baoming = packageName;
        return "包名已设置";
    }
};

/**
 * 主函数，程序入口
 */
function main(){
    // 清理之前的hook
    Java.perform(function() {
        console.log("应用新的Hook配置");
        
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
        
        start();
    });
}

// 初始执行
main();