/**
 * FD2游戏重新实现头文件
 * 基于IDA Pro MCP服务器对fd2.exe的逆向工程分析
 */

#ifndef FD2_REIMPL_H
#define FD2_REIMPL_H

#include <stdint.h>
#include <stdbool.h>

#ifdef USE_SDL
#include "fd2_sdl_renderer.h"
#endif

// 基本数据类型
typedef uint8_t byte;
typedef uint16_t word;
typedef uint32_t dword;

// 游戏常量
#define SCREEN_WIDTH 320
#define SCREEN_HEIGHT 200
#define PALETTE_SIZE 256
#define MAX_RESOURCES 1000
#define MAX_DAT_FILES 20

// Rendering开关：开启地图索引渲染覆盖层，便于阶段性验证渲染管线
// 未来可改为运行时开关或配置项
#ifndef ENABLE_MAP_INDEX_RENDER
#define ENABLE_MAP_INDEX_RENDER 1
#endif

// 文件句柄
typedef struct {
    byte* data;
    dword size;
    dword position;
} FileHandle;

// 资源表条目（8字节）
typedef struct {
    dword start_offset;
    dword end_offset;
    dword size;  // 计算得出
    byte* data;  // 指向数据的指针
} ResourceEntry;

// DAT文件信息
typedef struct {
    char filename[256];
    FileHandle handle;
    int resource_count;
    ResourceEntry* resources;  // 动态分配
} DatFile;

// 游戏状态
typedef struct {
    // 图形
    byte palette[PALETTE_SIZE][3];  // RGB调色板（8位）
    byte screen_buffer[SCREEN_WIDTH * SCREEN_HEIGHT];
    bool graphics_initialized;
    // 渲染开关（运行时控制）
    // 注意：Phase 3 Overlay 通过 render_map_overlay_runtime 控制
    
    // 文件系统
    DatFile dat_files[MAX_DAT_FILES];
    int dat_file_count;
    
    // SDL渲染器（如果启用）
    void* sdl_renderer;  // 指向SDLRenderer结构
    // 运行时地图索引渲染覆盖开关
    bool render_map_overlay_runtime;
    
    // 游戏状态
    bool running;
    int current_level;
    int score;
} GameState;

// 初始化函数
bool init_game(GameState* state);
bool init_graphics(GameState* state);
bool init_audio(GameState* state);
bool init_input(GameState* state);

// 文件系统函数
bool load_file(const char* filename, FileHandle* handle);
void close_file(FileHandle* handle);
byte read_byte(FileHandle* handle);
word read_word(FileHandle* handle);
dword read_dword(FileHandle* handle);
bool seek_file(FileHandle* handle, dword position);

// 资源管理函数
bool load_dat_file(GameState* state, const char* filename);
bool parse_dat_resources(DatFile* dat);
ResourceEntry* get_resource(DatFile* dat, int index);
byte* get_resource_data(DatFile* dat, int index, int* size);

// 图形函数（软件实现）
void set_palette(GameState* state, int start, int end, byte* palette_data);
void clear_screen(GameState* state, byte color);
void plot_pixel(GameState* state, int x, int y, byte color);
void draw_rect(GameState* state, int x, int y, int width, int height, byte color);
void draw_image(GameState* state, int x, int y, int width, int height, byte* image_data);
void draw_image_to_buffer(byte* dst, int dst_w, int dst_h, int x, int y, int w, int h, byte* src);

#ifdef USE_SDL
// SDL图形函数
bool init_sdl_renderer(GameState* state);
void sdl_set_palette(GameState* state, int start, int end, byte* palette_data);
void sdl_clear_screen(GameState* state, byte color);
void sdl_plot_pixel(GameState* state, int x, int y, byte color);
void sdl_render_frame(GameState* state);
void sdl_cleanup(GameState* state);
#endif

// 游戏逻辑函数
void update_game(GameState* state);
void render_game(GameState* state);
void handle_input(GameState* state);

// 主循环
void game_loop(GameState* state);

// 清理函数
void cleanup_game(GameState* state);

// 工具函数
byte* decode_palette_6bit(byte* data);
byte* decode_image_raw(byte* data, int width, int height);
byte* decode_image_rle(byte* data, int width, int height);
byte* decode_fdother_resource(byte* data, int size, int* width, int* height);
byte* decode_ani_resource(byte* data, int size, int* width, int* height);

#endif // FD2_REIMPL_H
