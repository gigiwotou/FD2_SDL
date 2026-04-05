/**
 * FD2 图像解码模块
 * 基于 fd2resviewer Python代码移植
 * 
 * 算法来源: tools/fd2resviewer/parsers/base_parser.py
 * 设计: 模块化，可替换为真正的逆向解析方法
 */

#ifndef FD2_IMAGE_H
#define FD2_IMAGE_H

#include <stdint.h>
#include <stdbool.h>

typedef uint8_t byte;
typedef uint16_t word;
typedef uint32_t dword;

#define PALETTE_SIZE 256
#define MAX_IMAGE_WIDTH 320
#define MAX_IMAGE_HEIGHT 200

/**
 * 调色板结构 (6位转8位)
 */
typedef struct {
    byte colors[PALETTE_SIZE][3];  // RGB 8-bit
} Palette;

/**
 * 简单图像结构
 */
typedef struct Image {
    int width;
    int height;
    byte* data;  // 调色板索引
} Image;

/**
 * 初始化调色板 - 从6位数据转换为8位
 * 来源: base_parser.py ColorPanel类
 * 
 * @param palette 输出调色板
 * @param data 6位调色板数据 (768字节)
 */
void palette_init_6bit(Palette* palette, const byte* data);

/**
 * 从DAT文件加载调色板 (资源0)
 * 来源: base_parser.py _load_from_dat()
 * 
 * @param palette 输出调色板
 * @param dat_file DAT文件路径
 * @return 0成功, -1失败
 */
int palette_load_from_dat(Palette* palette, const char* dat_file);

/**
 * 获取调色板颜色
 * 来源: base_parser.py ColorPanel.thisColor()
 * 
 * @param palette 调色板
 * @param index 颜色索引 (0-255)
 * @param out_rgb 输出RGB数组 [r, g, b]
 */
void palette_get_color(const Palette* palette, int index, byte out_rgb[3]);

/**
 * 解码普通BMP图像
 * 来源: base_parser.py BMPMaker.makeBMP()
 * 
 * @param data 图像数据
 * @param width 宽度
 * @param height 高度
 * @param palette 调色板
 * @return 分配的Image结构, 需要手动释放
 */
Image* image_decode_bmp(const byte* data, int width, int height, const Palette* palette);

/**
 * 解码面部/肖像图像 (带RLE变长解码)
 * 来源: base_parser.py BMPMaker.makeFaceBMP()
 * 
 * 特殊格式: 
 * - 前2字节: width
 * - 前2字节: height
 * - 后续: 变长RLE数据 (值>192表示重复次数)
 * 
 * @param data 图像数据
 * @param size 数据大小
 * @param palette 调色板
 * @return 分配的Image结构, 需要手动释放
 */
Image* image_decode_face(const byte* data, int size, const Palette* palette);

/**
 * 解码背景图像
 * 来源: base_parser.py BMPMaker.makeBgBMP()
 * 
 * @param data 图像数据
 * @param size 数据大小
 * @param palette 调色板
 * @return 分配的Image结构, 需要手动释放
 */
Image* image_decode_bg(const byte* data, int size, const Palette* palette);

/**
 * 释放图像
 */
void image_free(Image* img);

/**
 * 复制图像数据到目标缓冲区
 * 自动处理越界检查
 * 
 * @param dst 目标缓冲区
 * @param dst_w 目标宽度
 * @param dst_h 目标高度
 * @param x 目标X坐标
 * @param y 目标Y坐标
 * @param w 源宽度
 * @param h 源高度
 * @param src 源数据
 */
void image_blit(byte* dst, int dst_w, int dst_h, int x, int y, int w, int h, const byte* src);

/**
 * 快速单色填充
 */
void image_fill(byte* img, int w, int h, byte color);

/* Allocate an Image for raw palette-index data (width x height) */
Image* image_index_alloc(int width, int height);

/* Set a pixel value by palette index (not converted to RGB here) */
void image_set_pixel_index(Image* img, int x, int y, byte idx);


/* 渲染：将索引图像直接写入屏幕缓冲区（以调色板索引为单位） */
void image_render_to_screen(byte* screen, int screen_w, int screen_h, int x, int y, const Image* img);

/* Create an Image from a raw palette-index data buffer (width x height) */
Image* image_from_indices(const byte* indices, int width, int height);

/* Render a raw palette-index buffer directly to screen (no intermediate Image) */
void render_indices_to_screen(byte* screen, int screen_w, int screen_h, int x, int y, const byte* indices, int width, int height);

/* Decode resource by type into Image (Phase-4 readiness) */
Image* image_decode_resource_by_type(const char* type, const byte* data, int size, const Palette* palette);

#endif /* FD2_IMAGE_H */
