// 发布构建不额外打开控制台窗口。
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    hk_proton_desktop_lib::run();
}
