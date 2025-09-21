// 默认的hook配置
export const DEFAULT_HOOK_CONFIG = [
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
  }
];

// 默认的目标应用包名
export const DEFAULT_TARGET_PACKAGE = 'com.example.testoffridalab';

// 默认的设备ID
export const DEFAULT_DEVICE_ID = 'emulator-5554';