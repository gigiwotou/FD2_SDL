/**
 * FD2游戏重新实现主程序
 * 基于IDA Pro MCP服务器对fd2.exe的逆向工程分析
 */

#include "fd2_reimpl.h"
#ifdef USE_SDL
#include "fd2_sdl_renderer.h"
#endif
#include "../include/fd2_map.h"
#include "../include/fd2_image.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static GameState game_state;

static bool parse_dat_resources_internal(DatFile* dat) {
    if (!dat->handle.data || dat->handle.size < 6) {
        printf("[DAT] 文件太小或无效: %s\n", dat->filename);
        return false;
    }
    
    if (memcmp(dat->handle.data, "LLLLLL", 6) != 0) {
        printf("[DAT] 文件头无效: %s\n", dat->filename);
        return false;
    }
    
    int offset = 6;
    dat->resource_count = 0;
    dat->resources = NULL;
    
    while (offset + 8 <= (int)dat->handle.size) {
        dword start_offset = *(dword*)(dat->handle.data + offset);
        dword end_offset = *(dword*)(dat->handle.data + offset + 4);
        
        if (start_offset >= dat->handle.size || end_offset > dat->handle.size) {
            break;
        }
        if (start_offset >= end_offset) {
            break;
        }
        
        ResourceEntry* entry = (ResourceEntry*)realloc(dat->resources, (dat->resource_count + 1) * sizeof(ResourceEntry));
        if (!entry) {
            printf("[DAT] 内存分配失败\n");
            free(dat->resources);
            dat->resources = NULL;
            return false;
        }
        dat->resources = entry;
        
        ResourceEntry* e = &dat->resources[dat->resource_count];
        e->start_offset = start_offset;
        e->end_offset = end_offset;
        e->size = end_offset - start_offset;
        e->data = dat->handle.data + start_offset;
        
        dat->resource_count++;
        offset += 8;
    }
    
    printf("[DAT] %s: %d个资源\n", dat->filename, dat->resource_count);
    return true;
}

static byte ani_palette_buf[768];
static byte ani_screen_buf[64000];

static void do_h0(byte* d) { byte b = d[0]; dword v = (b<<16)|(b<<8)|b; dword* p=(dword*)ani_palette_buf; for(int i=0;i<96;i++)p[i]=v; }
static void do_h1(byte* d, int sz) { if(sz>768)sz=768; memcpy(ani_palette_buf,d,sz); }
static void do_h2(byte* d, int sz) {
    byte* dst=(byte*)ani_palette_buf; int filled=0,pos=0;
    while(filled<768&&pos<sz){byte b=d[pos++];if((b&0xC0)==0xC0){int run=b&0x3F;byte v=d[pos++];for(int j=0;j<run&&filled<768&&pos<sz;j++){*dst++=v;filled++;}}else{*dst++=b;filled++;}}
}
static void do_h3(byte* d, int sz) {
    int pos=0; if(pos>=sz)return;
    int count=d[pos++]; byte* dst=ani_palette_buf;
    for(int i=0;i<count&&pos+4<=sz;i++){int olo=d[pos++],ohi=d[pos++];int off=olo|(ohi<<8);int clo=d[pos++],chi=d[pos++];int cp=clo|(chi<<8);if(off>=0&&cp>0&&off+cp<=768&&pos+cp<=sz){memcpy(dst+off,d+pos,cp);}pos+=cp;}
}
static void do_h4(byte* d) { byte b=d[0]; dword v=(b<<16)|(b<<8)|b; dword* p=(dword*)ani_screen_buf; for(int i=0;i<10000;i++)p[i]=v; for(int i=40000;i<64000;i++)ani_screen_buf[i]=b; }
static void do_h5(byte* d) { memcpy(ani_screen_buf,d,64000); }
static void do_h6(byte* d, int sz) {
    byte* dst=(byte*)ani_screen_buf; int filled=0,pos=0;
    while(filled<64000&&pos<sz){byte b=d[pos++];if((b&0xC0)==0xC0){int run=b&0x3F;byte v=d[pos++];for(int j=0;j<run&&filled<64000&&pos<sz;j++){*dst++=v;filled++;}}else{*dst++=b;filled++;}}
}
static void do_h7(byte* d, int sz) {
    int pos=0; if(pos+2>sz)return;
    int lo=d[pos++],hi=d[pos++]; int count=lo|(hi<<8);
    for(int i=0;i<count&&pos+4<=sz;i++){int olo=d[pos++],ohi=d[pos++];int off=olo|(ohi<<8);int plo=d[pos++],phi=d[pos++];int pi=plo|(phi<<8);if(off>=0&&off<64000)ani_screen_buf[off]=(byte)pi;}
}
static void do_h8(byte* d, int sz) {
    int pos=0; if(pos+2>sz)return;
    int lo=d[pos++],hi=d[pos++]; int count=lo|(hi<<8);
    for(int i=0;i<count&&pos+5<=sz;i++){int olo=d[pos++],ohi=d[pos++];int off=olo|(ohi<<8);int slo=d[pos++],shi=d[pos++];int stride=slo|(shi<<8);byte v=d[pos++];for(int j=0;j<stride&&off+j<64000;j++)ani_screen_buf[off+j]=v;}
}
static void do_h9(byte* d, int sz) {
    int pos=0; if(pos+2>sz)return;
    int lo=d[pos++],hi=d[pos++]; int count=lo|(hi<<8);
    for(int i=0;i<count&&pos+4<=sz;i++){int olo=d[pos++],ohi=d[pos++];int off=olo|(ohi<<8);int slo=d[pos++],shi=d[pos++];int stride=slo|(shi<<8);if(off>=0&&stride>0&&off+stride<=64000&&pos+stride<=sz)memcpy(ani_screen_buf+off,d+pos,stride);pos+=stride;}
}

static void run_ani_command(int cmd, byte* data, int pos_in_block, int block_size) {
    int remaining = block_size - pos_in_block;
    switch(cmd) {
        case 0: do_h0(data+pos_in_block); break;
        case 1: do_h1(data+pos_in_block, remaining); break;
        case 2: do_h2(data+pos_in_block, remaining); break;
        case 3: do_h3(data+pos_in_block, remaining); break;
        case 4: do_h4(data+pos_in_block); break;
        case 5: do_h5(data+pos_in_block); break;
        case 6: do_h6(data+pos_in_block, remaining); break;
        case 7: do_h7(data+pos_in_block, remaining); break;
        case 8: do_h8(data+pos_in_block, remaining); break;
        case 9: do_h9(data+pos_in_block, remaining); break;
    }
}

static int load_ani_animation_frame(int block_index) {
    FILE* fp = fopen("ANI.DAT", "rb");
    if (!fp) return -1;
    
    fseek(fp, 4 * 0 + 6, SEEK_SET);
    dword offset;
    if (fread(&offset, 4, 1, fp) != 1) { fclose(fp); return -1; }
    
    fseek(fp, offset, SEEK_SET);
    byte header[173];
    if (fread(header, 1, 173, fp) != 173) { fclose(fp); return -1; }
    
    word block_count = *(word*)(header + 165);
    if (block_index < 0 || block_index >= block_count) { fclose(fp); return -1; }
    
    static byte block_data[64000];
    
    for (int i = 0; i < block_count; i++) {
        byte block_header[8];
        if (fread(block_header, 1, 8, fp) != 8) break;
        
        word size = *(word*)(block_header + 0);
        word cmd_count = *(word*)(block_header + 2);
        
        if (size == 0 || cmd_count == 0) continue;
        
        if (i == block_index) {
            if (size > 64000) size = 64000;
            if (fread(block_data, 1, size, fp) != (size_t)size) { fclose(fp); return -1; }
            
            int pos = 0;
            for (int c = 0; c < cmd_count && pos < size; c++) {
                byte cmd = block_data[pos++];
                if (cmd < 10) {
                    run_ani_command(cmd, block_data, pos, size);
                }
            }
            fclose(fp);
            return 1;
        }
        
        if (fseek(fp, size, SEEK_CUR) != 0) { fclose(fp); return -1; }
    }
    
    fclose(fp);
    return 0;
}

static int load_ani_animation(int index) {
    FILE* fp = fopen("ANI.DAT", "rb");
    if (!fp) {
        printf("[ANI] 无法打开ANI.DAT\n");
        return -1;
    }
    
    fseek(fp, 4 * index + 6, SEEK_SET);
    
    dword offset;
    if (fread(&offset, 4, 1, fp) != 1) {
        fclose(fp);
        return -1;
    }
    
    fseek(fp, offset, SEEK_SET);
    
    byte header[173];
    if (fread(header, 1, 173, fp) != 173) {
        fclose(fp);
        return -1;
    }
    
    word block_count = *(word*)(header + 165);
    printf("[ANI] 动画索引%d: %d个块\n", index, block_count);
    
    static byte block_data[64000];
    
    for (int i = 0; i < block_count; i++) {
        byte block_header[8];
        if (fread(block_header, 1, 8, fp) != 8) break;
        
        word size = *(word*)(block_header + 0);
        word cmd_count = *(word*)(block_header + 2);
        
        if (size == 0 || cmd_count == 0) continue;
        if (size > 64000) size = 64000;
        if (fread(block_data, 1, size, fp) != (size_t)size) break;
        
        int pos = 0;
        for (int c = 0; c < cmd_count && pos < size; c++) {
            byte cmd = block_data[pos++];
            if (cmd < 10) {
                run_ani_command(cmd, block_data, pos, size);
            }
        }
    }
    
    fclose(fp);
    return 0;
}

bool init_game(GameState* state) {
    memset(state, 0, sizeof(GameState));
    
    printf("初始化FD2游戏重新实现...\n");
    
    if (!init_graphics(state)) {
        printf("图形初始化失败\n");
        return false;
    }
    
    if (!init_audio(state)) {
        printf("音频初始化失败（可选）\n");
    }
    
    if (!init_input(state)) {
        printf("输入初始化失败\n");
        return false;
    }
    
    state->running = true;
    printf("游戏初始化完成\n");
    
    return true;
}

bool init_graphics(GameState* state) {
#ifdef USE_SDL
    if (!init_sdl_renderer(state)) {
        printf("SDL渲染器初始化失败，切换到控制台模式\n");
    } else {
        printf("图形初始化成功 (SDL2)\n");
    }
#else
    printf("图形初始化成功 (控制台模式)\n");
#endif
    
    state->graphics_initialized = true;
    return true;
}

bool init_audio(GameState* state) {
    (void)state;
    printf("音频系统初始化（模拟）\n");
    return true;
}

bool init_input(GameState* state) {
    (void)state;
    printf("输入系统初始化\n");
    return true;
}

bool load_file(const char* filename, FileHandle* handle) {
    FILE* file = fopen(filename, "rb");
    if (!file) {
        printf("无法打开文件: %s\n", filename);
        return false;
    }
    
    fseek(file, 0, SEEK_END);
    long size = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    handle->data = (byte*)malloc(size);
    if (!handle->data) {
        printf("内存分配失败\n");
        fclose(file);
        return false;
    }
    
    size_t read_size = fread(handle->data, 1, size, file);
    fclose(file);
    
    if (read_size != (size_t)size) {
        printf("文件读取不完整\n");
        free(handle->data);
        return false;
    }
    
    handle->size = size;
    handle->position = 0;
    
    printf("文件加载成功: %s (%ld字节)\n", filename, size);
    return true;
}

void close_file(FileHandle* handle) {
    if (handle->data) {
        free(handle->data);
        handle->data = NULL;
    }
    handle->size = 0;
    handle->position = 0;
}

byte read_byte(FileHandle* handle) {
    if (handle->position >= handle->size) return 0;
    return handle->data[handle->position++];
}

word read_word(FileHandle* handle) {
    byte low = read_byte(handle);
    byte high = read_byte(handle);
    return (high << 8) | low;
}

dword read_dword(FileHandle* handle) {
    word low = read_word(handle);
    word high = read_word(handle);
    return (high << 16) | low;
}

bool seek_file(FileHandle* handle, dword position) {
    if (position > handle->size) return false;
    handle->position = position;
    return true;
}

bool load_dat_file(GameState* state, const char* filename) {
    if (state->dat_file_count >= MAX_DAT_FILES) {
        printf("DAT文件数量已达上限\n");
        return false;
    }
    
    FileHandle handle;
    if (!load_file(filename, &handle)) {
        return false;
    }
    
    DatFile* dat = &state->dat_files[state->dat_file_count];
    strncpy(dat->filename, filename, sizeof(dat->filename) - 1);
    dat->handle = handle;
    
    if (!parse_dat_resources_internal(dat)) {
        printf("解析资源表失败: %s\n", filename);
        close_file(&dat->handle);
        return false;
    }
    
    state->dat_file_count++;
    return true;
}

static DatFile* find_dat(GameState* state, const char* filename) {
    for (int i = 0; i < state->dat_file_count; i++) {
        if (strcmp(state->dat_files[i].filename, filename) == 0) {
            return &state->dat_files[i];
        }
    }
    return NULL;
}

static byte* get_resource_by_name_index(GameState* state, const char* datname, int index, int* out_size) {
    DatFile* dat = find_dat(state, datname);
    if (!dat) return NULL;
    if (index < 0 || index >= dat->resource_count) return NULL;
    if (out_size) *out_size = dat->resources[index].size;
    return dat->resources[index].data;
}

bool parse_dat_resources(DatFile* dat) {
    return parse_dat_resources_internal(dat);
}

ResourceEntry* get_resource(DatFile* dat, int index) {
    if (index < 0 || index >= dat->resource_count) return NULL;
    return &dat->resources[index];
}

byte* get_resource_data(DatFile* dat, int index, int* size) {
    ResourceEntry* entry = get_resource(dat, index);
    if (!entry) return NULL;
    if (size) *size = entry->size;
    return entry->data;
}

void set_palette(GameState* state, int start, int end, byte* palette_data) {
    for (int i = start; i <= end && i < PALETTE_SIZE; i++) {
        int idx = (i - start) * 3;
        state->palette[i][0] = palette_data[idx];
        state->palette[i][1] = palette_data[idx + 1];
        state->palette[i][2] = palette_data[idx + 2];
    }
}

void clear_screen(GameState* state, byte color) {
    memset(state->screen_buffer, color, SCREEN_WIDTH * SCREEN_HEIGHT);
}

void plot_pixel(GameState* state, int x, int y, byte color) {
    if (x >= 0 && x < SCREEN_WIDTH && y >= 0 && y < SCREEN_HEIGHT) {
        state->screen_buffer[y * SCREEN_WIDTH + x] = color;
    }
}

void draw_rect(GameState* state, int x, int y, int width, int height, byte color) {
    for (int dy = 0; dy < height; dy++) {
        for (int dx = 0; dx < width; dx++) {
            plot_pixel(state, x + dx, y + dy, color);
        }
    }
}

void draw_image(GameState* state, int x, int y, int width, int height, byte* image_data) {
    for (int dy = 0; dy < height; dy++) {
        for (int dx = 0; dx < width; dx++) {
            int src_idx = dy * width + dx;
            if (src_idx < width * height) {
                plot_pixel(state, x + dx, y + dy, image_data[src_idx]);
            }
        }
    }
}

void draw_image_to_buffer(byte* dst, int dst_w, int dst_h, int x, int y, int w, int h, byte* src) {
    for (int dy = 0; dy < h; dy++) {
        for (int dx = 0; dx < w; dx++) {
            int px = x + dx;
            int py = y + dy;
            if (px >= 0 && px < dst_w && py >= 0 && py < dst_h) {
                int src_idx = dy * w + dx;
                int dst_idx = py * dst_w + px;
                dst[dst_idx] = src[src_idx];
            }
        }
    }
}

#ifdef USE_SDL
bool init_sdl_renderer(GameState* state) {
    if (fd2_sdl_init_renderer()) {
        state->sdl_renderer = get_sdl_renderer();
        return true;
    }
    return false;
}

void sdl_set_palette(GameState* state, int start, int end, byte* palette_data) {
    fd2_sdl_set_palette(start, end, palette_data);
}

void sdl_clear_screen(GameState* state, byte color) {
    fd2_sdl_clear_screen(color);
}

void sdl_plot_pixel(GameState* state, int x, int y, byte color) {
    fd2_sdl_plot_pixel(x, y, color);
}

void sdl_render_frame(GameState* state) {
    fd2_sdl_render_frame(state->screen_buffer);
}

void sdl_cleanup(GameState* state) {
    fd2_sdl_cleanup();
    state->sdl_renderer = NULL;
}
#endif

void update_game(GameState* state) {
    (void)state;
}

void render_game(GameState* state) {
    // Phase-2: render current map as an index-based image if available
    map_render_current_map_to_screen(state->screen_buffer, SCREEN_WIDTH, SCREEN_HEIGHT);
#if ENABLE_MAP_INDEX_RENDER
    {
        // Phase-3: render a small test overlay using direct index data for demonstration
        // Simple 4x4 checkerboard of palette indices
        const byte indices[16] = {
            0, 1, 2, 3,
            4, 5, 6, 7,
            8, 9,10,11,
            12,13,14,15
        };
        // render at (2,2) as a demonstration overlay
        render_indices_to_screen(state->screen_buffer, SCREEN_WIDTH, SCREEN_HEIGHT, 2, 2, indices, 4, 4);
    }
    #endif
#ifdef USE_SDL
    if (state->sdl_renderer) {
        sdl_render_frame(state);
    } else {
        static const char* chars = " .:-=+*#%@";
        for (int y = 0; y < SCREEN_HEIGHT; y += 4) {
            for (int x = 0; x < SCREEN_WIDTH; x += 2) {
                byte color = state->screen_buffer[y * SCREEN_WIDTH + x];
                int idx = color * 9 / 255;
                putchar(chars[idx]);
            }
            putchar('\n');
        }
    }
#else
    static const char* chars = " .:-=+*#%@";
    for (int y = 0; y < SCREEN_HEIGHT; y += 4) {
        for (int x = 0; x < SCREEN_WIDTH; x += 2) {
            byte color = state->screen_buffer[y * SCREEN_WIDTH + x];
            int idx = color * 9 / 255;
            putchar(chars[idx]);
        }
        putchar('\n');
    }
#endif
}

void handle_input(GameState* state) {
    (void)state;
}

void game_loop(GameState* state) {
    printf("游戏循环开始\n");
    
#ifdef USE_SDL
    if (state->sdl_renderer) {
        uint32_t last_time = SDL_GetTicks();
        const uint32_t target_fps = 30;
        const uint32_t frame_delay = 1000 / target_fps;
        
        while (state->running) {
            if (!fd2_sdl_process_events()) {
                state->running = false;
                break;
            }
            
            uint32_t current_time = SDL_GetTicks();
            uint32_t delta = current_time - last_time;
            
            if (delta > frame_delay) {
                handle_input(state);
                update_game(state);
                render_game(state);
                last_time = current_time;
            }
            
            SDL_Delay(1);
        }
    } else {
        int frame_count = 0;
        while (state->running && frame_count < 3) {
            handle_input(state);
            update_game(state);
            render_game(state);
            frame_count++;
        }
        state->running = false;
    }
#else
    int frame_count = 0;
    while (state->running && frame_count < 3) {
        handle_input(state);
        update_game(state);
        render_game(state);
        frame_count++;
    }
    state->running = false;
#endif
    
    printf("游戏循环结束\n");
}

void cleanup_game(GameState* state) {
    printf("清理游戏资源...\n");
    
    for (int i = 0; i < state->dat_file_count; i++) {
        DatFile* dat = &state->dat_files[i];
        if (dat->resources) {
            free(dat->resources);
        }
        close_file(&dat->handle);
    }
    
#ifdef USE_SDL
    sdl_cleanup(state);
#endif
    
    printf("游戏清理完成\n");
}

byte* decode_palette_6bit(byte* data) {
    static byte palette_8bit[PALETTE_SIZE * 3];
    for (int i = 0; i < PALETTE_SIZE; i++) {
        byte r6 = data[i * 3] & 0x3F;
        byte g6 = data[i * 3 + 1] & 0x3F;
        byte b6 = data[i * 3 + 2] & 0x3F;
        palette_8bit[i * 3] = (r6 << 2) | (r6 >> 4);
        palette_8bit[i * 3 + 1] = (g6 << 2) | (g6 >> 4);
        palette_8bit[i * 3 + 2] = (b6 << 2) | (b6 >> 4);
    }
    return palette_8bit;
}

byte* decode_image_raw(byte* data, int width, int height) {
    return data;
}

byte* decode_image_rle(byte* data, int width, int height) {
    static byte* decoded = NULL;
    if (!decoded) {
        decoded = (byte*)malloc(width * height);
    }
    
    int decoded_pos = 0;
    int data_pos = 0;
    
    while (decoded_pos < width * height && data_pos < width * height * 2) {
        byte marker = data[data_pos++];
        if (marker == 0x00) {
            byte count = data[data_pos++];
            if (count > 0) {
                byte value = data[data_pos++];
                for (int i = 0; i < count && decoded_pos < width * height; i++) {
                    decoded[decoded_pos++] = value;
                }
            } else {
                while (decoded_pos % width != 0 && decoded_pos < width * height) {
                    decoded[decoded_pos++] = 0;
                }
            }
        } else {
            decoded[decoded_pos++] = marker;
        }
    }
    
    return decoded;
}

byte* decode_fdother_resource(byte* data, int size, int* width, int* height) {
    if (size == 768) {
        *width = 0;
        *height = 0;
        return NULL;
    }
    
    int offset_count = 0;
    dword offsets[32];
    
    for (int i = 0; i < 32 && (dword)(i * 4 + 4) < (dword)size; i++) {
        dword offset = *(dword*)(data + i * 4);
        if (offset < (dword)size && (i == 0 || offset > offsets[i-1])) {
            offsets[offset_count++] = offset;
        } else {
            break;
        }
    }
    
    if (offset_count >= 2) {
        dword block_size = offsets[1] - offsets[0];
        
        int sprite_widths[] = {16, 22, 32, 44, 48, 64};
        int sprite_heights[] = {16, 22, 32, 11, 10, 8};
        
        for (int i = 0; i < 6; i++) {
            if (sprite_widths[i] * sprite_heights[i] == (int)block_size) {
                *width = sprite_widths[i];
                *height = sprite_heights[i];
                return data + offsets[0];
            }
        }
        
        if (block_size > 0 && block_size <= 640) {
            int possible_heights[] = {200, 100, 50, 25};
            for (int j = 0; j < 4; j++) {
                int h = possible_heights[j];
                if ((dword)(block_size * h) <= (dword)size) {
                    *width = block_size;
                    *height = h;
                    return data + offsets[0];
                }
            }
        }
    }
    
    if (size >= 320 * 200) {
        *width = 320;
        *height = 200;
        return data;
    }
    
    int common_widths[] = {320, 256, 160, 80};
    int common_heights[] = {200, 240, 100, 50};
    
    for (int i = 0; i < 4; i++) {
        if (common_widths[i] * common_heights[i] <= size) {
            *width = common_widths[i];
            *height = common_heights[i];
            return data;
        }
    }
    
    return NULL;
}

byte* decode_ani_resource(byte* data, int size, int* width, int* height) {
    if (size < 4) return NULL;
    
    dword first_dword = *(dword*)data;
    
    if (first_dword > 0x1F000000) {
        int header_end = 0;
        for (int i = 0; i < size - 1; i++) {
            byte b = data[i];
            if ((b >= 0x20 && b <= 0x7E) || b == '\n' || b == '\r' || b == '\t') {
                continue;
            } else if (b == 0x1A) {
                header_end = i + 1;
                break;
            } else {
                header_end = i;
                break;
            }
        }
        
        byte* binary_data = data + header_end;
        int binary_size = size - header_end;
        
        if (binary_size >= 320 * 200) {
            *width = 320;
            *height = 200;
            return binary_data;
        }
        
        int common_widths[] = {320, 256, 160, 80};
        int common_heights[] = {200, 240, 100, 50};
        
        for (int i = 0; i < 4; i++) {
            if (common_widths[i] * common_heights[i] <= binary_size) {
                *width = common_widths[i];
                *height = common_heights[i];
                return binary_data;
            }
        }
        
        return NULL;
    }
    
    dword actual_offset = first_dword;
    if (actual_offset >= (dword)size) {
        actual_offset = 0;
    }
    
    byte* resource_data = data + actual_offset;
    int resource_size = size - actual_offset;
    
    if (resource_size >= 320 * 200) {
        *width = 320;
        *height = 200;
        return resource_data;
    }
    
    return NULL;
}

int main(int argc, char* argv[]) {
    (void)argc; (void)argv;
    printf("FD2游戏重新实现 - 基于IDA Pro MCP服务器分析\n");
    printf("=============================================\n");
    
    if (!init_game(&game_state)) {
        printf("游戏初始化失败\n");
        return 1;
    }
    
    printf("\n=== FD2.exe 启动流程 (基于IDA Pro分析) ===\n");
    printf("按照fd2.exe的sub_111BA(filename, oldPtr, index)格式加载资源\n\n");
    
    load_dat_file(&game_state, "FDOTHER.DAT");
    load_dat_file(&game_state, "FDTXT.DAT");
    load_dat_file(&game_state, "FDFIELD.DAT");
    load_dat_file(&game_state, "FDSHAP.DAT");
    load_dat_file(&game_state, "ANI.DAT");
    load_dat_file(&game_state, "FIGANI.DAT");
    load_dat_file(&game_state, "TITLE.DAT");
    load_dat_file(&game_state, "BG.DAT");
    load_dat_file(&game_state, "TAI.DAT");
    load_dat_file(&game_state, "DATO.DAT");
    load_dat_file(&game_state, "FDMUS.DAT");
    
    printf("\n=== 按fd2.exe顺序加载关键资源 ===\n");
    int rsize;
    byte* r;
    
    r = get_resource_by_name_index(&game_state, "FDOTHER.DAT", 0, &rsize);
    if (r && rsize == 768) {
        printf("[FDOTHER.DAT][0] 768字节 - 调色板\n");
        byte* palette8 = decode_palette_6bit(r);
        set_palette(&game_state, 0, 255, palette8);
    }
    
    r = get_resource_by_name_index(&game_state, "FDOTHER.DAT", 1, &rsize);
    printf("[FDOTHER.DAT][1] %d字节 - 主精灵数据\n", rsize);
    
    r = get_resource_by_name_index(&game_state, "FDOTHER.DAT", 2, &rsize);
    printf("[FDOTHER.DAT][2] %d字节 - 精灵数据\n", rsize);
    
    r = get_resource_by_name_index(&game_state, "FDOTHER.DAT", 3, &rsize);
    printf("[FDOTHER.DAT][3] %d字节 - 精灵数据\n", rsize);
    
    r = get_resource_by_name_index(&game_state, "FDOTHER.DAT", 4, &rsize);
    if (r && rsize == 768) {
        printf("[FDOTHER.DAT][4] 768字节 - 备用调色板\n");
    }
    
    r = get_resource_by_name_index(&game_state, "FDOTHER.DAT", 5, &rsize);
    printf("[FDOTHER.DAT][5] %d字节 - 动画/精灵数据\n", rsize);
    
    r = get_resource_by_name_index(&game_state, "FDOTHER.DAT", 6, &rsize);
    printf("[FDOTHER.DAT][6] %d字节 - 关卡数据\n", rsize);
    
    r = get_resource_by_name_index(&game_state, "FDTXT.DAT", 0, &rsize);
    printf("[FDTXT.DAT][0] %d字节 - 文本资源\n", rsize);
    
    r = get_resource_by_name_index(&game_state, "FDOTHER.DAT", 31, &rsize);
    printf("[FDOTHER.DAT][31] %d字节 - 扩展数据\n", rsize);
    
    printf("\n=== 加载ANI.DAT动画 ===\n");
    for (int i = 0; i < 5; i++) {
        FILE* fp = fopen("ANI.DAT", "rb");
        if (fp) {
            fseek(fp, 4 * i + 6, SEEK_SET);
            dword offset;
            if (fread(&offset, 4, 1, fp) == 1) {
                fseek(fp, offset, SEEK_SET);
                byte header[27];
                if (fread(header, 1, 27, fp) == 27) {
                    char marker[16] = {0};
                    memcpy(marker, header + 11, 15);
                    printf("[ANI.DAT][%d] offset=0x%X, marker='%s'\n", i, offset, marker);
                }
                fseek(fp, offset + 165, SEEK_SET);
                word block_count;
                if (fread(&block_count, 2, 1, fp) == 1) {
                    printf("  -> %d 动画块\n", block_count);
                }
            }
            fclose(fp);
        }
    }
    
    printf("\n=== 播放标题动画 (ANI.DAT资源0的前32帧) ===\n");
    for (int frame = 0; frame < 32; frame++) {
        memset(ani_screen_buf, 0, 64000);
        load_ani_animation_frame(frame);
        
#ifdef USE_SDL
        if (game_state.sdl_renderer) {
            fd2_sdl_render_ani_frame(ani_screen_buf, 320, 200);
            SDL_Delay(50);
            if (!fd2_sdl_process_events()) {
                printf("用户关闭窗口\n");
                cleanup_game(&game_state);
                return 0;
            }
        } else
#endif
        {
            memcpy(game_state.screen_buffer, ani_screen_buf, 64000);
            if (frame == 0 || frame == 16 || frame == 31) {
                printf("--- 标题动画帧 %d ---\n", frame + 1);
                static const char* chars = " .:-=+*#%@";
                for (int y = 0; y < SCREEN_HEIGHT; y += 4) {
                    for (int x = 0; x < SCREEN_WIDTH; x += 2) {
                        byte color = game_state.screen_buffer[y * SCREEN_WIDTH + x];
                        int idx = color * 9 / 255;
                        putchar(chars[idx]);
                    }
                    putchar('\n');
                }
            }
        }
    }
    
    printf("\n=== 播放关卡选择动画 (ANI.DAT资源0帧32-63) ===\n");
    for (int frame = 32; frame < 64; frame++) {
        memset(ani_screen_buf, 0, 64000);
        load_ani_animation_frame(frame);
        
#ifdef USE_SDL
        if (game_state.sdl_renderer) {
            fd2_sdl_render_ani_frame(ani_screen_buf, 320, 200);
            SDL_Delay(50);
            if (!fd2_sdl_process_events()) {
                printf("用户关闭窗口\n");
                cleanup_game(&game_state);
                return 0;
            }
        } else
#endif
        {
            memcpy(game_state.screen_buffer, ani_screen_buf, 64000);
            if (frame == 32 || frame == 48 || frame == 63) {
                printf("--- 关卡选择帧 %d ---\n", frame + 1);
                static const char* chars = " .:-=+*#%@";
                for (int y = 0; y < SCREEN_HEIGHT; y += 4) {
                    for (int x = 0; x < SCREEN_WIDTH; x += 2) {
                        byte color = game_state.screen_buffer[y * SCREEN_WIDTH + x];
                        int idx = color * 9 / 255;
                        putchar(chars[idx]);
                    }
                    putchar('\n');
                }
            }
        }
    }
    
    printf("\n=== 游戏资源已加载 ===\n");
    printf("fd2.exe 重新实现已完成初始化\n");
    printf("ANI.DAT: 96帧动画已解码\n");
    printf("FDOTHER.DAT: 主游戏资源已加载\n");
    printf("FDTXT.DAT: 文本资源已加载\n");
    
#ifdef USE_SDL
    if (game_state.sdl_renderer) {
        printf("\nSDL2图形模式: 动画已显示在窗口中\n");
        printf("按ESC或关闭窗口退出...\n");
        while (fd2_sdl_process_events()) {
            SDL_Delay(100);
        }
    } else
#endif
    {
        printf("\n按任意键退出...\n");
        getchar();
    }
    
    cleanup_game(&game_state);
    printf("程序结束\n");
    return 0;
}
