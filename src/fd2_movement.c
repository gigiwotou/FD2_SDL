/**
 * FD2 单位移动系统实现
 * 基于IDA Pro逆向分析，支持地形移动cost
 * 
 * 地形cost系统 (与原版游戏一致):
 * - 使用带权重BFS计算移动范围
 * - 不同地形有不同的移动cost (平原=1, 森林=2, 山脉=3等)
 * - 水和墙不可通行 (cost=99)
 */

#include "fd2_movement.h"
#include "fd2_unit.h"
#include "fd2_resources.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static PathNode g_path_nodes[MAX_MAP_DIM][MAX_MAP_DIM];

static const byte g_terrain_move_cost[16] = {
    1,   // TERRAIN_PLAINS (平原)
    2,   // TERRAIN_FOREST (森林)
    3,   // TERRAIN_MOUNTAIN (山脉)
    99,  // TERRAIN_WATER (水 - 不可通行)
    99,  // TERRAIN_WALL (墙 - 不可通行)
    1,   // TERRAIN_ROAD (道路)
    1,   // TERRAIN_BRIDGE (桥梁)
    1,   // TERRAIN_CASTLE (城堡)
    1,   // TERRAIN_VILLAGE (村庄)
    1,   // TERRAIN_PLAINS2
    2,   // TERRAIN_FOREST2
    3,   // TERRAIN_MOUNTAIN2
    1,   // TERRAIN_DESERT
    1,   // TERRAIN_SNOW
    1,   // TERRAIN_LAVA
    1    // TERRAIN_CAVE
};

static short heuristic(byte x1, byte y1, byte x2, byte y2) {
    return (short)(abs((int)x1 - (int)x2) + abs((int)y1 - (int)y2));
}

static byte get_terrain_cost(const MapData* map, byte x, byte y) {
    if (!map || x >= map->width || y >= map->height) return 99;
    int tile_id = map->tile_ids[y * map->width + x];
    byte terrain = (byte)(tile_id & 0x0F);
    if (terrain >= 16) terrain = 0;
    return g_terrain_move_cost[terrain];
}

int movement_is_tile_passable(const MapData* map, byte x, byte y) {
    if (!map) return 0;
    if (x >= map->width || y >= map->height) return 0;
    byte cost = get_terrain_cost(map, x, y);
    return cost < 99;
}

static void reset_path_nodes(byte width, byte height) {
    for (byte y = 0; y < height; y++) {
        for (byte x = 0; x < width; x++) {
            g_path_nodes[x][y].g_cost = 0;
            g_path_nodes[x][y].h_cost = 0;
            g_path_nodes[x][y].f_cost = 0;
            g_path_nodes[x][y].parent_x = 0xFF;
            g_path_nodes[x][y].parent_y = 0xFF;
            g_path_nodes[x][y].in_open_set = false;
            g_path_nodes[x][y].in_closed_set = false;
        }
    }
}

int movement_calculate_move_range(const Unit* unit, const MapData* map, MoveRange* range) {
    if (!unit || !map || !range) return -1;
    
    memset(range, 0, sizeof(MoveRange));
    range->move_range = (byte)unit->move_range;
    
    if (range->move_range == 0) return 0;
    
    byte start_x = unit->x;
    byte start_y = unit->y;
    
    for (byte y = 0; y < map->height; y++) {
        for (byte x = 0; x < map->width; x++) {
            range->reachable[x][y] = false;
        }
    }
    
    typedef struct {
        byte x, y;
        short g;
    } QueueNode;
    
    QueueNode queue[MAX_MAP_DIM * MAX_MAP_DIM];
    int queue_head = 0;
    int queue_tail = 0;
    
    queue[queue_tail].x = start_x;
    queue[queue_tail].y = start_y;
    queue[queue_tail].g = 0;
    queue_tail++;
    
    range->reachable[start_x][start_y] = true;
    range->reachable_count = 1;
    
    static const byte dx[4] = {0, 1, 0, (byte)-1};
    static const byte dy[4] = {(byte)-1, 0, 1, 0};
    
    while (queue_head < queue_tail) {
        QueueNode current = queue[queue_head];
        queue_head++;
        
        for (int dir = 0; dir < 4; dir++) {
            byte nx = current.x + dx[dir];
            byte ny = current.y + dy[dir];
            
            if (!movement_is_tile_passable(map, nx, ny)) continue;
            
            byte move_cost = get_terrain_cost(map, nx, ny);
            short new_cost = current.g + move_cost;
            
            if (new_cost > range->move_range) continue;
            if (range->reachable[nx][ny]) continue;
            
            range->reachable[nx][ny] = true;
            range->reachable_count++;
            
            queue[queue_tail].x = nx;
            queue[queue_tail].y = ny;
            queue[queue_tail].g = new_cost;
            queue_tail++;
        }
    }
    
    return range->reachable_count;
}

int movement_find_path(const MapData* map, byte start_x, byte start_y, 
                       byte target_x, byte target_y, UnitPath* path) {
    if (!map || !path) return -1;
    
    memset(path, 0, sizeof(UnitPath));
    
    if (!movement_is_tile_passable(map, target_x, target_y)) {
        return -1;
    }
    
    if (start_x == target_x && start_y == target_y) {
        return 0;
    }
    
    reset_path_nodes(map->width, map->height);
    
    typedef struct {
        byte x, y;
        short f;
    } OpenNode;
    
    OpenNode open_list[MAX_MAP_DIM * MAX_MAP_DIM];
    int open_count = 0;
    
    g_path_nodes[start_x][start_y].g_cost = 0;
    g_path_nodes[start_x][start_y].h_cost = heuristic(start_x, start_y, target_x, target_y);
    g_path_nodes[start_x][start_y].f_cost = g_path_nodes[start_x][start_y].g_cost + g_path_nodes[start_x][start_y].h_cost;
    g_path_nodes[start_x][start_y].in_open_set = true;
    
    open_list[open_count].x = start_x;
    open_list[open_count].y = start_y;
    open_list[open_count].f = g_path_nodes[start_x][start_y].f_cost;
    open_count++;
    
    static const byte dx[4] = {0, 1, 0, (byte)-1};
    static const byte dy[4] = {(byte)-1, 0, 1, 0};
    
    byte found_x = 0xFF, found_y = 0xFF;
    
    while (open_count > 0) {
        short min_f = 9999;
        int min_idx = 0;
        for (int i = 0; i < open_count; i++) {
            byte ox = open_list[i].x;
            byte oy = open_list[i].y;
            if (g_path_nodes[ox][oy].f_cost < min_f) {
                min_f = g_path_nodes[ox][oy].f_cost;
                min_idx = i;
            }
        }
        
        byte cx = open_list[min_idx].x;
        byte cy = open_list[min_idx].y;
        
        open_list[min_idx] = open_list[open_count - 1];
        open_count--;
        
        g_path_nodes[cx][cy].in_open_set = false;
        g_path_nodes[cx][cy].in_closed_set = true;
        
        if (cx == target_x && cy == target_y) {
            found_x = cx;
            found_y = cy;
            break;
        }
        
        for (int dir = 0; dir < 4; dir++) {
            byte nx = cx + dx[dir];
            byte ny = cy + dy[dir];
            
            if (!movement_is_tile_passable(map, nx, ny)) continue;
            if (g_path_nodes[nx][ny].in_closed_set) continue;
            
            byte move_cost = get_terrain_cost(map, nx, ny);
            short new_g = g_path_nodes[cx][cy].g_cost + move_cost;
            
            if (!g_path_nodes[nx][ny].in_open_set) {
                g_path_nodes[nx][ny].g_cost = new_g;
                g_path_nodes[nx][ny].h_cost = heuristic(nx, ny, target_x, target_y);
                g_path_nodes[nx][ny].f_cost = g_path_nodes[nx][ny].g_cost + g_path_nodes[nx][ny].h_cost;
                g_path_nodes[nx][ny].parent_x = cx;
                g_path_nodes[nx][ny].parent_y = cy;
                g_path_nodes[nx][ny].in_open_set = true;
                
                open_list[open_count].x = nx;
                open_list[open_count].y = ny;
                open_list[open_count].f = g_path_nodes[nx][ny].f_cost;
                open_count++;
            } else if (new_g < g_path_nodes[nx][ny].g_cost) {
                g_path_nodes[nx][ny].g_cost = new_g;
                g_path_nodes[nx][ny].f_cost = g_path_nodes[nx][ny].g_cost + g_path_nodes[nx][ny].h_cost;
                g_path_nodes[nx][ny].parent_x = cx;
                g_path_nodes[nx][ny].parent_y = cy;
            }
        }
    }
    
    if (found_x == 0xFF) {
        return -1;
    }
    
    byte path_x[MAX_PATH_LENGTH];
    byte path_y[MAX_PATH_LENGTH];
    byte path_len = 0;
    
    byte px = target_x;
    byte py = target_y;
    
    while (!(px == start_x && py == start_y)) {
        path_x[path_len] = px;
        path_y[path_len] = py;
        path_len++;
        
        if (path_len >= MAX_PATH_LENGTH) break;
        
        byte pp_x = g_path_nodes[px][py].parent_x;
        byte pp_y = g_path_nodes[px][py].parent_y;
        
        if (pp_x == 0xFF) break;
        
        px = pp_x;
        py = pp_y;
    }
    
    path_x[path_len] = start_x;
    path_y[path_len] = start_y;
    path_len++;
    
    for (int i = 0; i < path_len / 2; i++) {
        byte tx = path_x[i];
        byte ty = path_y[i];
        path_x[i] = path_x[path_len - 1 - i];
        path_y[i] = path_y[path_len - 1 - i];
        path_x[path_len - 1 - i] = tx;
        path_y[path_len - 1 - i] = ty;
    }
    
    for (int i = 0; i < path_len && i < MAX_PATH_LENGTH; i++) {
        path->path_x[i] = path_x[i];
        path->path_y[i] = path_y[i];
    }
    
    path->path_length = path_len;
    path->current_index = 0;
    
    return path_len;
}

void movement_execute_path(Unit* unit, UnitPath* path) {
    if (!unit || !path) return;
    if (path->path_length == 0) return;
    if (path->current_index >= path->path_length) return;
    
    byte next_x = path->path_x[path->current_index];
    byte next_y = path->path_y[path->current_index];
    
    unit->x = next_x;
    unit->y = next_y;
    path->current_index++;
    
    if (next_x > unit->x) unit->direction = DIR_RIGHT;
    else if (next_x < unit->x) unit->direction = DIR_LEFT;
    else if (next_y > unit->y) unit->direction = DIR_DOWN;
    else if (next_y < unit->y) unit->direction = DIR_UP;
}

bool movement_has_path(const UnitPath* path) {
    return path && path->path_length > 0 && path->current_index < path->path_length;
}

byte movement_get_path_length(const UnitPath* path) {
    return path ? path->path_length : 0;
}

void movement_clear_path(UnitPath* path) {
    if (path) {
        memset(path, 0, sizeof(UnitPath));
    }
}
