
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
            console.log(classz[i])
        }
    }
    })
}
function get_all_method_from_classname(class_name){
    Java.perform(function(){
        var classname="java.lang.String";
        var clazz = Java.use(classname);
        var methods = clazz.class.getDeclaredMethods();
        for(var i=0;i<methods.length;i++){
            console.log(methods[i].getName())
        }
    })
}


/**
 * 主函数，程序入口
 */
function main(){
    var baoming="java.lang.String"
    console.log("开始枚举类："+baoming+"\n");
    get_all_method_from_classname();
    //start();
    //setImmediate(start);
}
main();