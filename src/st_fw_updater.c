/* 
 * This file is part of the distribution (https://github.com/stmicroelectronics-acp/atlas-fw-updater).
 * Copyright (c) 2018 STMicroelectronics.
 * 
 * This program is free software: you can redistribute it and/or modify  
 * it under the terms of the GNU General Public License as published by  
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but 
 * WITHOUT ANY WARRANTY; without even the implied warranty of 
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU 
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License 
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

/* 
 * File:   main.c
 * Author: Salvatore LA MALFA
 *
 * Created on 4 October, 2018, 4:44 PM
 */
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <linux/i2c.h>
#include <linux/i2c-dev.h>
#include <string.h>
#include <time.h>

#define debug_print(fmt, ...) do { if (DEBUG) printf(fmt, ##__VA_ARGS__); } while (0)

#define DEBUG 0

#define I2C_SLAVE_ADDRESS       0x49
#define FTB_HEADER_LENGTH       64
#define FTB_HEADER_SIGNATURE    (uint32_t)0xAA55AA55

#define FLASH_ERASE_CMD_TYPE    0x02
#define FLASH_DMA_CMD_TYPE      0x05
#define DMA_CHUNK               32
#define FLASH_CHUNK             (64 * 1024)

#define FW_UPDATE_MAX_RETRY     3

#define VERSION 1.01

int device_fd;

typedef struct {
    uint16_t fw_version;
    uint16_t config_id;
    uint8_t* fw_data;
    size_t fw_data_length;
    uint8_t* config_data;
    size_t config_data_length;
    uint8_t* cx_data;
    size_t cx_data_length;
} firmware_file;

typedef struct {
    uint16_t hw_id;
    uint16_t fw_version;
    uint16_t config_id;
    uint8_t cx_version_cx_area;
    uint8_t cx_version_config_area;
} fingertip_version_info;

void sleep_ms(unsigned long ms_to_sleep) {
    
    struct timespec t;
    
    t.tv_sec = 0;
    t.tv_nsec = 1000000 * ms_to_sleep;
    nanosleep(&t, NULL);
}

uint32_t get_uint32_le(uint8_t* p) {
    return (uint32_t)(*p + (*(p + 1) << 8) + (*(p + 2) << 16) + (*(p + 3) << 24));
}

uint32_t get_uint16_le(uint8_t* p) {
    return (uint16_t)(*p + (*(p + 1) << 8));
}

int i2c_open(const char* i2c_dev) {
           
    device_fd = open(i2c_dev, O_RDWR);
    if (device_fd < 0) {
        debug_print("[ERROR] could not open %s\n", i2c_dev);
        return -ENODEV;
    }
    
    debug_print("[INFO] %s opened successfully, fid: %d\n", i2c_dev, device_fd);
    return 0;
}

int i2c_write_read(uint8_t* command, int command_length, uint8_t* read_data, int read_count) {
    
    struct i2c_msg msg[2];
    struct i2c_rdwr_ioctl_data data;
    
    // write message
    msg[0].addr = (__u16)I2C_SLAVE_ADDRESS;
    msg[0].flags = (__u16)0;
    msg[0].buf = (__u8*)command;
    msg[0].len = (__u16)command_length;
        
    // read message
    msg[1].addr = (__u16)I2C_SLAVE_ADDRESS;
    msg[1].flags = I2C_M_RD;
    msg[1].buf = (__u8*)read_data;
    msg[1].len = (__u16)read_count;
    
    data.msgs = &msg[0];
    data.nmsgs = 2;
    
    return ioctl(device_fd, I2C_RDWR, &data);
}

int i2c_write(uint8_t* command, int command_length) {
    
    struct i2c_msg msg[1];
    struct i2c_rdwr_ioctl_data data;
    
    // write message
    msg[0].addr = (__u16)I2C_SLAVE_ADDRESS;
    msg[0].flags = (__u16)0;
    msg[0].buf = (__u8*)command;
    msg[0].len = (__u16)command_length;            
    
    data.msgs = &msg[0];
    data.nmsgs = 1;
    
    return ioctl(device_fd, I2C_RDWR, &data);
}

int clear_event_fifo() {
    
    uint8_t cmd_pop_event[] = {0x85};
    uint8_t fifo_event[8] = {0x00};
    
    debug_print("[INFO] flushing event fifo...\n");
    
    for (int i = 0; i < 64; i++) {
        
        if (i2c_write_read(cmd_pop_event, 1, fifo_event, 8) < 0) {
            
            debug_print("[ERROR] could not flush event fifo\n");
            return -EIO;
        }
        
        if (fifo_event[0] == 0x00) {
            
            debug_print("[INFO] flushing event fifo done\n");
            return 0;
        }
        
        debug_print("[INFO] fifo event: %02X %02X %02X %02X %02X %02X %02X %02X\n", fifo_event[0], fifo_event[1], fifo_event[2], fifo_event[3], fifo_event[4], fifo_event[5], fifo_event[6], fifo_event[7]);        
    }
    
    return 0;
}

int set_host_interrupt_enable(int enable) {
    
    uint8_t cmd[] = {0xB6, 0x00, 0x2C, 0x41};
    
    if (enable == 0) {
        cmd[3] = 0x00;
    }
    
    debug_print("[INFO] host interrupt enable: %d\n", enable);
    
    return i2c_write(cmd, 4);
}

int set_hid_enable(int enable) {
    
    uint8_t cmd[4] = {0x00};
    
    if (enable) {
        
        
        // system reset (this will enable HID mode by FW)        
        cmd[0] = 0xB6;
        cmd[1] = 0x00;
        cmd[2] = 0x28;
        cmd[3] = 0x80;
               
        if (i2c_write(cmd, 4) < 0) {
            debug_print("[ERROR] could not system reset\n");
            return -EIO;
        }
        
        sleep_ms(250);
        
        
        // HID SET POWER
        cmd[0] = 0xCD;
        cmd[1] = 0xCF;
        cmd[2] = 0x00;
        cmd[3] = 0x08;
        
        if (i2c_write(cmd, 4) < 0) {
        
            debug_print("[ERROR] could not perform i2c write\n");
            return -EIO;
        }
                        
    } else {
        // HID SET POWER OFF
        cmd[0] = 0xCD;
        cmd[1] = 0xCF;
        cmd[2] = 0x00;
        cmd[3] = 0x00;
        
        if (i2c_write(cmd, 4) < 0) {
        
            debug_print("[ERROR] could not perform i2c write\n");
            return -EIO;
        }
        
        // disable HID mode by HW register
        cmd[0] = 0xB6;
        cmd[1] = 0x00;
        cmd[2] = 0xA8;
        cmd[3] = 0x00;
        
        if (i2c_write(cmd, 4) < 0) {
        
            debug_print("[ERROR] could not perform i2c write\n");
            return -EIO;
        }
        
        // flush FIFO
        cmd[0] = 0xA1;
        
        if (i2c_write(cmd, 1) < 0) {
        
            debug_print("[ERROR] could not perform i2c write\n");
            return -EIO;
        }
        
        sleep_ms(10);
        

    }     
    
    debug_print("[INFO] hid enable set to %d\n", enable);
    
    return 0;
}

int get_hid_status(int* enabled) {
    
    uint8_t cmd[] = {0xB6, 0x00, 0x04};
    uint8_t chip_id[3] = {0x00};
    
    if (i2c_write_read(cmd, 3, chip_id, 3) < 0) {
        debug_print("[ERROR] could not read chip id\n");
        return -EIO;
    }
    
    if(chip_id[0] == 0x36 && chip_id[1] == 0x70) {
        *enabled = 1;
        return 0;
    }
    
    if(chip_id[1] == 0x36 && chip_id[2] == 0x70) {
        *enabled = 0;
        return 0;
    }
    
    debug_print("[ERROR] unexpected chip id: %02X %02X %02X\n", chip_id[0], chip_id[1], chip_id[2]);
    
    return -EIO;
    
}

int read_config_register(uint16_t address, uint32_t* data) {
    
    uint8_t address_msb = (uint8_t)((address & 0xFF00) >> 8);
    uint8_t address_lsb = (uint8_t)(address & 0xFF);
    uint8_t cmd_config_id[] = {0xB2, address_msb, address_lsb, 0x04};
    uint8_t cmd_pop_event[] = {0x85};
    uint8_t fifo_event[8] = {0x00};
    
    int found = 0;
    
    if (set_host_interrupt_enable(0) < 0) {
        
        debug_print("[ERROR] could not disable host interrupts\n");
        return -EIO;
    }
    
    if (clear_event_fifo() < 0) {
        
        debug_print("[ERROR] could not clear event fifo\n");
        return -EIO;
    }
    
    if (i2c_write(cmd_config_id, 4) < 0) {
        
        debug_print("[ERROR] could not write config id read cmd\n");
        return -EIO;
    }
    
    sleep_ms(5);
    
    for (int i = 0; i < 64; i++) {
        if (i2c_write_read(cmd_pop_event, 1, fifo_event, 8) < 0) {
            
            debug_print("[ERROR] could not pop FIFO event\n");
            return -EIO;
        }        
        
        if (fifo_event[0] != 0x00) {
            
            debug_print("[INFO] fifo event: %02X %02X %02X %02X %02X %02X %02X %02X\n", fifo_event[0], fifo_event[1], fifo_event[2], fifo_event[3], fifo_event[4], fifo_event[5], fifo_event[6], fifo_event[7]);
        }
        
        
        if (fifo_event[0] == 0x12 && fifo_event[1] == cmd_config_id[1] && fifo_event[2] == cmd_config_id[2]) {
            
            *data = (uint32_t)((fifo_event[3] << 24) + (fifo_event[4] << 16) + (fifo_event[5] << 8) + fifo_event[6]); 
            debug_print("[INFO] config register @0x%04X = 0x%08X\n", address, *data);
            found = 1;
            break;
        }
            
    } 
    
    if (set_host_interrupt_enable(1) < 0) {
        
        debug_print("[ERROR] could not enable host interrupts\n");
        return -EIO;
    }
    
    if (!found) {
        
        debug_print("[ERROR] could not read config register\n");
        return -EIO;
    }
    
    return 0;
    
}

int read_cx_version_from_cx_area(uint8_t* cx_version) {
    
    // request COMP_RD_MS_TCH
    uint8_t cmd_request_host_data[] = {0xB8, 0x02, 0x00};
    
    uint8_t cmd_read_host_data[] = {0xD0, 0x80, 0x00};
    
    uint8_t buff[17];
    
    if (i2c_write(cmd_request_host_data, 3) < 0) {
        
        debug_print("[ERROR] could not request host data\n");
        return -EIO;
    }
    
    sleep_ms(50);
    
    if (i2c_write_read(cmd_read_host_data, 3, buff, 17) < 0) {
        
        debug_print("[ERROR] could not read host data\n");
        return -EIO;
    }
    
    if (buff[1] == 0xA5 && buff[2] == 0x02 && buff[3] == 0x00) {
        *cx_version = buff[9];        
    } else {
        *cx_version = 0xFF;
        debug_print("[ERROR] unexpected host data signature: %02X %02X %02X\n", buff[1], buff[2], buff[3]);
        return -EIO;
    }
    
        
    return 0;
    
    
}

int parse_ftb_file(const char* path_to_ftb_file, firmware_file* file) {
    
    uint8_t header[FTB_HEADER_LENGTH];
    size_t read_bytes_count = 0;
    FILE* fp = NULL;
    
    file->fw_data = NULL;
    file->cx_data = NULL;
    file->config_data = NULL;
    
    if ((fp = fopen(path_to_ftb_file, "r")) == NULL) {
        
        debug_print("[ERROR] could not open %s\n", path_to_ftb_file);        
        return -EIO;
    }
    
    if ((read_bytes_count = fread(header, 1, FTB_HEADER_LENGTH, fp)) != FTB_HEADER_LENGTH) {
        
        debug_print("[ERROR] could not read ftb header, %d\n", read_bytes_count);
        fclose(fp);
        return -EIO;
    }
    
    uint32_t ftb_signature = get_uint32_le(&header[0]);
    
    if (ftb_signature != FTB_HEADER_SIGNATURE) {
        
        debug_print("[ERROR] unexpected signature in ftb header: 0x%08X\n", ftb_signature);
        fclose(fp);
        return -EIO;
    }
    
    file->fw_version    = get_uint16_le(&header[16]);
    file->config_id     = get_uint16_le(&header[20]);        
    
    file->fw_data_length        = get_uint32_le(&header[44]);
    file->config_data_length    = get_uint32_le(&header[48]);
    file->cx_data_length        = get_uint32_le(&header[52]);
    
    debug_print("[INFO] ftb fw_version: 0x%04X\n", file->fw_version);
    debug_print("[INFO] ftb config_id: 0x%04X\n", file->config_id);
    debug_print("[INFO] ftb fw_data_length: %d bytes\n", file->fw_data_length);
    debug_print("[INFO] ftb config_data_length: %d bytes\n", file->config_data_length);
    debug_print("[INFO] ftb cx_data_length: %d bytes\n", file->cx_data_length);
    
    if (file->fw_data_length > 0) {
        
        file->fw_data = malloc(file->fw_data_length * sizeof(uint8_t));
        if (file->fw_data == NULL) {
            
            debug_print("[ERROR] could not allocate fw_data buffer\n");
            fclose(fp);
            return -ENOMEM;
        }
        
        if ((read_bytes_count = fread(file->fw_data, 1, file->fw_data_length, fp)) != file->fw_data_length) {
        
            debug_print("[ERROR] could not read ftb fw_data\n");
            fclose(fp);
            free(file->fw_data);
            return -EIO;
        }        
    }
    
    if (file->config_data_length > 0) {
        
        file->config_data = malloc(file->config_data_length * sizeof(uint8_t));
        if (file->config_data == NULL) {
            
            debug_print("[ERROR] could not allocate config_data buffer\n");         
            fclose(fp);            
            free(file->fw_data);
            return -ENOMEM;
        }
        
        if ((read_bytes_count = fread(file->config_data, 1, file->config_data_length, fp)) != file->config_data_length) {
        
            debug_print("[ERROR] could not read ftb config_data\n");
            fclose(fp);
            free(file->fw_data);
            free(file->config_data);
            return -EIO;
        }        
    }
    
    if (file->cx_data_length > 0) {
        
        file->cx_data = malloc(file->cx_data_length * sizeof(uint8_t));
        if (file->cx_data == NULL) {
            
            debug_print("[ERROR] could not allocate cx_data buffer\n");         
            fclose(fp);            
            free(file->fw_data);
            free(file->config_data);
            return -ENOMEM;
        }
        
        if ((read_bytes_count = fread(file->cx_data, 1, file->cx_data_length, fp)) != file->cx_data_length) {
        
            debug_print("[ERROR] could not read ftb cx_data\n");
            fclose(fp);
            free(file->fw_data);
            free(file->config_data);
            free(file->cx_data);
            return -EIO;
        }        
    }
    
    debug_print("[INFO] ftb file %s parsed successfully\n", path_to_ftb_file);
    fclose(fp);
    return 0;       
}

int read_fingertip_version_info(fingertip_version_info* info) {
    
    uint8_t cmd[] = {0xB6, 0x00, 0x04};
    uint8_t chip_id[8] = {0x00};
    int offset = 1;
    uint32_t config_reg = 0;
    
    if (set_hid_enable(0) < 0) {
        
        debug_print("[ERROR] could not disable HID mode\n");
        return -EIO;
    }                    
    
    if (i2c_write_read(cmd, 3, chip_id, 8) < 0) {
        debug_print("[ERROR] could not read chip id\n");
        return -EIO;
    }
    
    info->hw_id = (uint16_t)((chip_id[offset] << 8) + chip_id[1 + offset]);
    info->fw_version = (uint16_t)((chip_id[5 + offset] << 8) + chip_id[4 + offset]);
    info->config_id = 0x0000;
    info->cx_version_config_area = 0x00;
    info->cx_version_cx_area = 0xFF;
    
    debug_print("[INFO] device hw_id: 0x%04X\n", info->hw_id);
    debug_print("[INFO] device fw_version: 0x%04X\n", info->fw_version); 
    
    if (info->fw_version != 0) {
        
        // read the config id
        if (read_config_register(0x0000, &config_reg) < 0) {
        
            debug_print("[WARNING] could not get config id\n");
            info->fw_version = 0x0000; // fw is not running, this will force fw update
            return 0;
            
        } else {
                                           
            uint8_t id_lsb = (uint8_t)((config_reg & 0xFF0000) >> 16);
            uint8_t id_msb = (uint8_t)((config_reg & 0xFF00) >> 8);
                   
            info->config_id = (uint16_t)((id_msb << 8) + id_lsb);
            debug_print("[INFO] device config_id: 0x%04X\n", info->config_id);
        }
        
        // read the cx tune version from config area                
        if (read_config_register(0x0731, &config_reg) < 0) {
        
            debug_print("[WARNING] could not get config id\n");
            info->fw_version = 0x0000; // fw is not running, this will force fw update
            return 0;
            
        } else {
        
            info->cx_version_config_area = (uint8_t)((config_reg & 0xFF000000) >> 24);
            debug_print("[INFO] device cx_version_config_area: 0x%02X\n", info->cx_version_config_area);
        }
        
        // read the cx tune version from cx area
        if (read_cx_version_from_cx_area(&info->cx_version_cx_area) < 0) {
            
            debug_print("[WARNING] could not get cx version from cx area\n");
            info->fw_version = 0x0000; // fw is not running, this will force fw update
            return 0;
            
        } else {
            
            debug_print("[INFO] device cx_version_cx_area: 0x%02X\n", info->cx_version_cx_area);
        }
        
    }
                                      
    if (set_hid_enable(1) < 0) {
        
        debug_print("[ERROR] could not enable HID mode\n");
        return -EIO;
    } 
            
    return 0;
}

int autotune() {
    
    uint8_t cmd_autotune[] = {0xA5};
    uint8_t cmd_pop_fifo_event[] = {0x85};
    uint8_t fifo_ev[8] = {0x00};    
    
    int error_count = 0;
    int timeout = 1;
    
    if (set_hid_enable(0) < 0) {
        
        debug_print("[ERROR] could not disable hid mode\n");
        return -EIO;
    }
    
    if (clear_event_fifo() < 0) {
        
        debug_print("[ERROR] could not clear event fifo\n");
        return -EIO;
    }
    
    sleep_ms(150);
    
    if (i2c_write(cmd_autotune, 1) < 0) {
        
        debug_print("[ERROR] could not send autotune command\n");
        return -EIO;
    }
    
    for (int i = 0; i < 1000; i++) {
        
        if (i2c_write_read(cmd_pop_fifo_event, 1, fifo_ev, 8) < 0) {
            
            debug_print("[ERROR] could not pop FIFO event\n");
            return -EIO;
        }
        
        if (fifo_ev[0] != 0x00) {
            
            debug_print("[INFO] %02X %02X %02X %02X %02X %02X %02X %02x\n", fifo_ev[0], fifo_ev[1], fifo_ev[2], fifo_ev[3], fifo_ev[4], fifo_ev[5], fifo_ev[6], fifo_ev[7]);
        }
        
        if (fifo_ev[0] == 0x0F) {
            
            error_count++;
        }
        
        if (fifo_ev[0] == 0x16 && fifo_ev[1] == 0x07) {
            
            debug_print("[INFO] autotune completed with %d errors after %d ms\n", error_count, (i * 10));
            timeout = 0;
            break;
        }
        
        sleep_ms(10);
    }        
    
    if (set_hid_enable(1) < 0) {
        
        debug_print("[ERROR] could not enable back hid mode\n");
        return -EIO;
    }
    
    if (error_count > 0 || timeout > 0) {
        
        debug_print("[ERROR] autotune failed, error count %d, timeout %d\n", error_count, timeout);
        return -EIO;
    }
    
    return 0;
    
    
}

int poll_for_flash_ready(uint8_t type, unsigned long timeout_ms) {
    
    int i = 0; 
    int ready = 0;
    uint8_t cmd[] = {0xF9, type};
    uint8_t data[] = {0x00};
    
    for (; i < (timeout_ms / 10); i++) {
        
        if (i2c_write_read(cmd, 2, data, 1) < 0) {
            return -EIO;
        }
        
        if ((data[0] & 0x80) == 0) {
            
            ready = 1;
            break;
        }
        sleep_ms(10);
    }
    
    if (ready) {
        debug_print("[INFO] flash ready after %d ms\n", (i * 10));
        return 0;
    } else {
        debug_print("[ERROR] flash ready timeout after %d ms\n", (i * 10));
        return -ETIME;
    }
    
    
}

int fill_memory(uint32_t address, uint8_t* data, int data_length) {
            
    uint8_t cmd_flash_dma[] = {0xFA, 0x05, 0xC0};
    
    int remaining = data_length;
    int to_write = 0;
    int byte_block = 0;
    int wheel = 0;
    
    uint32_t address_now = 0;
    
    uint8_t buff[DMA_CHUNK + 3];
    
    while (remaining > 0) {
        
        byte_block = 0;
        address_now = 0;
        while (byte_block < FLASH_CHUNK && remaining > 0) {
            
            if (remaining >= DMA_CHUNK) {
                
                if ((byte_block + DMA_CHUNK) <= FLASH_CHUNK) {
                    
                    to_write = DMA_CHUNK;
                    remaining -= DMA_CHUNK;
                    byte_block += DMA_CHUNK;                    
                } else {
                    
                    to_write = FLASH_CHUNK - byte_block;
                    remaining -= to_write;
                    byte_block += to_write; 
                }
                
            } else {
                
                if ((byte_block + remaining) <= FLASH_CHUNK) {
                    
                    to_write = remaining;
                    byte_block += remaining;
                    remaining = 0;
                } else {
                    
                    to_write = FLASH_CHUNK - byte_block;
                    remaining -= to_write;
                    byte_block += to_write;
                }
            }
            
            buff[0] = 0xF8;
            buff[1] = (uint8_t)((address_now & 0xFF00) >> 8);
            buff[2] = (uint8_t)(address_now & 0xFF);
            
            memcpy(&buff[3], data, to_write);
            
            if (i2c_write(buff, 3 + to_write) < 0) {
                
                debug_print("[ERROR] error while filling memory\n");
                return -EIO;
            }
            
            address_now += to_write;
            data += to_write;
            
        }
        
        byte_block = byte_block / 4 - 1;
        address_now = address + ((wheel * FLASH_CHUNK) / 4);
        
        buff[0] = 0xFA;
        buff[1] = 0x06;
        buff[2] = 0x00;
        buff[3] = 0x00;
        buff[4] = (uint8_t)(address_now & 0xFF);
        buff[5] = (uint8_t)((address_now & 0xFF00) >> 8);
        buff[6] = (uint8_t)(byte_block & 0xFF);
        buff[7] = (uint8_t)((byte_block & 0xFF00) >> 8);
        buff[8] = 0x00;
        
        if (i2c_write(buff, 9) < 0) {
            
            debug_print("[ERROR] error before flash DMA \n");
            return -EIO;
        }
        
        if (i2c_write(cmd_flash_dma, 3) < 0) {
            
            debug_print("[ERROR] error during flash DMA\n");
            return -EIO;
        }
        
        if (poll_for_flash_ready(FLASH_DMA_CMD_TYPE, 5000) < 0) {

            debug_print("[ERROR] error while polling for flash ready\n");
            return -EIO;
        }
        
        wheel++;
        
    }
    
    debug_print("[INFO] %d bytes written at 0x%08X\n", data_length, address);    
    return 0;
    
}

int flash_burn(firmware_file* file, int preserve_cx, int autotune_if_needed) {
    
    uint8_t cmd_system_reset[]      = {0xB6, 0x00, 0x28, 0x80};
    uint8_t cmd_warm_boot[]         = {0xB6, 0x00, 0x1E, 0x38};
    uint8_t cmd_unlock_flash[]      = {0xF7, 0x74, 0x45};
    uint8_t cmd_unlock_erase[]      = {0xFA, 0x72, 0x03};
    uint8_t cmd_erase_code_page[]   = {0xFA, 0x02, 0x80};
    uint8_t cmd_erase_config_page[] = {0xFA, 0x02, 0xBF};
    
            
    if (file->fw_data_length > 0) {             
        
        uint32_t crc        = get_uint32_le(&(file->fw_data[0]));
        uint32_t length     = get_uint32_le(&(file->fw_data[4]));
        uint32_t not_crc    = get_uint32_le(&(file->fw_data[8]));
        uint32_t not_length = get_uint32_le(&(file->fw_data[12]));
        
        debug_print("[INFO] fw_data CRC: 0x%08X\n", crc);
        debug_print("[INFO] fw_data length: %d\n", length);
        
        if ((crc != ~not_crc) || (length != ~not_length)) {
            
            debug_print("[ERROR] fw_data header does not match the expected format\n");
            return -EINVAL;
        }
    }
    
    if (file->config_data_length > 0 && file->config_data_length != 2048) {
        
        debug_print("[ERROR] unexpected config_data_length %d\n", file->config_data_length);
        return -EINVAL;
    }
    
    debug_print("[INFO] firmware file is a well formed FTD3 file\n"); 
    
    debug_print("[INFO] system reset\n");
    if (i2c_write(cmd_system_reset, 4) < 0) {
        
        debug_print("[ERROR] could not system reset\n");
        return -EIO;
    }
    
    sleep_ms(200);
    
    // disable HID mode
    if (set_hid_enable(0) < 0) {
        
        debug_print("[ERROR] could not disable HID mode\n");
        return -EIO;        
    }
    
    if (i2c_write(cmd_warm_boot, 4) < 0) {
        
        debug_print("[ERROR] could not send warm boot cmd\n");
        return -EIO;
    }
    
    if (i2c_write(cmd_unlock_flash, 3) < 0) {
        
        debug_print("[ERROR] could not send unlock flash cmd\n");
        return -EIO;
    }
    
    if (i2c_write(cmd_unlock_erase, 3) < 0) {
        
        debug_print("[ERROR] could not send unlock erase cmd\n");
        return -EIO;
    }
    
    if (file->fw_data != NULL) {
        
        for (int i = 0; i < 60; i++) {
            
            debug_print("[INFO] erasing code page %d...\n", i);
            cmd_erase_code_page[2] = (uint8_t)(0x80 + i);
                
            if (i2c_write(cmd_erase_code_page, 3) < 0) {

                debug_print("[ERROR] could not send code page erase cmd\n");
                return -EIO;
            }
            
            if (poll_for_flash_ready(FLASH_ERASE_CMD_TYPE, 500) < 0) {
                
                debug_print("[ERROR] error while polling for flash ready\n");
                return -EIO;
            }            
            
        }
        
        debug_print("[INFO] code area erased successfully\n");
            
    }
    
    if (file->config_data != NULL) {
                                
        if (i2c_write(cmd_erase_config_page, 3) < 0) {

            debug_print("[ERROR] could not send code page erase cmd\n");
            return -EIO;
        }
        
        if (poll_for_flash_ready(FLASH_ERASE_CMD_TYPE, 500) < 0) {
                
            debug_print("[ERROR] error while polling for flash ready\n");
            return -EIO;
        }
        
        debug_print("[INFO] config area erased successfully\n");                    
    }
    
    if (!preserve_cx) {
        
        for (int i = 61; i < 63; i++) {
            
            debug_print("[INFO] erasing code page %d...\n", i);
            cmd_erase_code_page[2] = (uint8_t)(0x80 + i);
                
            if (i2c_write(cmd_erase_code_page, 3) < 0) {

                debug_print("[ERROR] could not send code page erase cmd\n");
                return -EIO;
            }
            
            if (poll_for_flash_ready(FLASH_ERASE_CMD_TYPE, 500) < 0) {
                
                debug_print("[ERROR] error while polling for flash ready\n");
                return -EIO;
            }            
            
        }
        
        debug_print("[INFO] cx area erased successfully\n");
        
    }
    
    if (file->fw_data != NULL) {
        
        debug_print("[INFO] flashing code...\n");
        if (fill_memory(0x00000000, file->fw_data, file->fw_data_length) < 0) {
            
            debug_print("[ERROR] could not flash code section\n");
            return -EIO;
        }
    }
    
    if (file->config_data != NULL) {
        
        debug_print("[INFO] flashing config...\n");
        if (fill_memory(0x0000FC00, file->config_data, file->config_data_length) < 0) {
            
            debug_print("[ERROR] could not flash config section\n");
            return -EIO;
        }
    }
    
    if (file->cx_data != NULL) {
        
        debug_print("[INFO] flashing cx...\n");
        if (fill_memory(0x0000F400, file->cx_data, file->cx_data_length) < 0) {
            
            debug_print("[ERROR] could not flash cx section\n");
            return -EIO;
        }
    }
    
    debug_print("[INFO] system reset\n");
    if (i2c_write(cmd_system_reset, 4) < 0) {
        
        debug_print("[ERROR] could not system reset\n");
        return -EIO;
    }
    
    sleep_ms(250);
    
    // disable HID mode
    if (set_hid_enable(0) < 0) {
        
        debug_print("[ERROR] could not disable HID mode\n");
        return -EIO;        
    }
    
    fingertip_version_info info;
    
    if (read_fingertip_version_info(&info) < 0) {
        
        debug_print("[ERROR] could not read version info\n");
        return -EIO;
    }        
    
    if (file->fw_data != NULL) {
            
        if (info.fw_version != file->fw_version) {
        
            debug_print("[ERROR] fw version mismatch after flash burn\n");
            return -EIO;
        }                
    }
    
    if (file->config_data != NULL) {
            
        if (info.config_id != file->config_id) {
        
            debug_print("[ERROR] config id mismatch after flash burn\n");
            return -EIO;
        }                
    }
    
    debug_print("[INFO] flash burned successfully\n");            
    
    if (autotune_if_needed) {
        
        if (info.cx_version_config_area != info.cx_version_cx_area) {
            debug_print("[INFO] cx tune version mismatch\n");
            
            if (autotune() < 0) {
                
                debug_print("[ERROR] could not perform autotune\n");
                return -EIO;
            }
            
            debug_print("[INFO] autotune completed successfully\n");
        } else {
            
            debug_print("[INFO] cx tune version match, skip autotune\n");
        }
    }
    
    return 0;
    
}

int flash_erase() {
    
    uint8_t cmd_system_reset[]      = {0xB6, 0x00, 0x28, 0x80};
    uint8_t cmd_warm_boot[]         = {0xB6, 0x00, 0x1E, 0x38};
    uint8_t cmd_unlock_flash[]      = {0xF7, 0x74, 0x45};
    uint8_t cmd_unlock_erase[]      = {0xFA, 0x72, 0x03};
    uint8_t cmd_erase_code_page[]   = {0xFA, 0x02, 0x80};
    uint8_t cmd_erase_config_page[] = {0xFA, 0x02, 0xBF};
    
    debug_print("[INFO] system reset\n");
    if (i2c_write(cmd_system_reset, 4) < 0) {
        
        debug_print("[ERROR] could not system reset\n");
        return -EIO;
    }
    
    sleep_ms(250);
    
    // disable HID mode
    if (set_hid_enable(0) < 0) {
        
        debug_print("[ERROR] could not disable HID mode\n");
        return -EIO;        
    }
    
    if (i2c_write(cmd_warm_boot, 4) < 0) {
        
        debug_print("[ERROR] could not send warm boot cmd\n");
        return -EIO;
    }
    
    if (i2c_write(cmd_unlock_flash, 3) < 0) {
        
        debug_print("[ERROR] could not send unlock flash cmd\n");
        return -EIO;
    }
    
    if (i2c_write(cmd_unlock_erase, 3) < 0) {
        
        debug_print("[ERROR] could not send unlock erase cmd\n");
        return -EIO;
    }
    
            
    for (int i = 0; i < 60; i++) {

        debug_print("[INFO] erasing code page %d...\n", i);
        cmd_erase_code_page[2] = (uint8_t)(0x80 + i);

        if (i2c_write(cmd_erase_code_page, 3) < 0) {

            debug_print("[ERROR] could not send code page erase cmd\n");
            return -EIO;
        }

        if (poll_for_flash_ready(FLASH_ERASE_CMD_TYPE, 500) < 0) {

            debug_print("[ERROR] error while polling for flash ready\n");
            return -EIO;
        }            

    }

    debug_print("[INFO] code area erased successfully\n");                        
                                
    if (i2c_write(cmd_erase_config_page, 3) < 0) {

        debug_print("[ERROR] could not send code page erase cmd\n");
        return -EIO;
    }

    if (poll_for_flash_ready(FLASH_ERASE_CMD_TYPE, 500) < 0) {

        debug_print("[ERROR] error while polling for flash ready\n");
        return -EIO;
    }

    debug_print("[INFO] config area erased successfully\n");                                
        
    for (int i = 61; i < 63; i++) {

        debug_print("[INFO] erasing code page %d...\n", i);
        cmd_erase_code_page[2] = (uint8_t)(0x80 + i);

        if (i2c_write(cmd_erase_code_page, 3) < 0) {

            debug_print("[ERROR] could not send code page erase cmd\n");
            return -EIO;
        }

        if (poll_for_flash_ready(FLASH_ERASE_CMD_TYPE, 500) < 0) {

            debug_print("[ERROR] error while polling for flash ready\n");
            return -EIO;
        }            

    }

    debug_print("[INFO] cx area erased successfully\n");
    
    debug_print("[INFO] system reset\n");
    if (i2c_write(cmd_system_reset, 4) < 0) {
        
        debug_print("[ERROR] could not system reset\n");
        return -EIO;
    }
    
    sleep_ms(250);
    
    return 0;
    
}



void print_usage() {
    
    printf("*************************************************************************\n");
    printf("**           STMicroelectronics Fingertip FW Updater V%.2f             **\n", VERSION);
    printf("*************************************************************************\n");
    printf("**                    salvatore.lamalfa@st.com                         **\n");
    printf("*************************************************************************\n");
    printf("** Command Format:                                                     **\n");
    printf("** [cmd] [arg-1] [arg-2] ... [arg-N]                                   **\n");
    printf("** flash_program /dev/i2c-1 /path/to/firmware_file.ftb                 **\n");
    printf("** get_firmware_file_info /path/to/firmware_file.ftb                   **\n");
    printf("** get_device_info /dev/i2c-1                                          **\n");
    printf("** autotune /dev/i2c-1                                                 **\n");
    printf("*************************************************************************\n");
    printf("*************************************************************************\n\n");
}

/*
 * 
 */
int main(int argc, char** argv) {
        
    char command[64];
    char arg1[512];
    char arg2[512];
    
    if (argc < 3) {
        
        print_usage();
        return (EXIT_SUCCESS);
        
    } else if (argc == 3) { 
        
        strncpy(command, argv[1], 64);    
        strncpy(arg1, argv[2], 512);   
        debug_print("[INFO] command: %s\n", command); 
        debug_print("[INFO] arg1: %s\n", arg1);                                
        
        if (strcmp(command, "get_firmware_file_info") == 0) {
            
            firmware_file file;
            
            if (parse_ftb_file(arg1, &file) < 0) {
                
                printf("[ERROR] could not get ftb file info for %s\n", arg1);
                return (EXIT_FAILURE);
            }
            
            printf("FW:%04X CFG:%04X\n", file.fw_version, file.config_id);
            
            free(file.fw_data);
            free(file.config_data);
            free(file.cx_data);
            
            return (EXIT_SUCCESS);
        }                
        
        if (strcmp(command, "get_device_info") == 0) {
            
            if (i2c_open(arg1) < 0) {
                
                printf("[ERROR] %s is not a valid i2c-dev filenode\n", arg1);
                close(device_fd);
                return (EXIT_FAILURE);
            }
            
            fingertip_version_info info;
            
            if (read_fingertip_version_info(&info) < 0) {
                
                printf("[ERROR] could not read fingertip info\n");
                close(device_fd);
                return (EXIT_FAILURE);
            }
            
            printf("HW:%04X FW:%04X CFG:%04X CX_VER_CFG:%02X CX_VER_CX:%02X\n", info.hw_id, info.fw_version, info.config_id, info.cx_version_config_area, info.cx_version_cx_area);
            
            close(device_fd);
            
            return (EXIT_SUCCESS);
            
        }
        
        if (strcmp(command, "flash_erase") == 0) {
            
            if (i2c_open(arg1) < 0) {
                
                printf("[ERROR] %s is not a valid i2c-dev filenode\n", arg1);
                close(device_fd);
                return (EXIT_FAILURE);
            }                        
            
            if (flash_erase() < 0) {
                
                printf("[ERROR] could not erase flash\n");
                close(device_fd);
                return (EXIT_FAILURE);
            }
            
            printf("[INFO] flash erased successfully\n");
            
            close(device_fd);
            
            return (EXIT_SUCCESS);
            
        }
        
        if (strcmp(command, "autotune") == 0) {
            
            if (i2c_open(arg1) < 0) {
                
                printf("[ERROR] %s is not a valid i2c-dev filenode\n", arg1);
                close(device_fd);
                return (EXIT_FAILURE);
            }                        
            
            if (autotune() < 0) {
                
                printf("[ERROR] autotune failed\n");
                close(device_fd);
                return (EXIT_FAILURE);
            }
            
            printf("[INFO] autotune completed successfully\n");
            
            close(device_fd);
            
            return (EXIT_SUCCESS);
            
        }
        
        printf("[ERROR] unrecognized command: %s\n", command);
        print_usage();
        return (EXIT_FAILURE);
                               
    } else if (argc == 4) {
        
        strncpy(command, argv[1], 64);    
        strncpy(arg1, argv[2], 512);   
        strncpy(arg2, argv[3], 512);   
        debug_print("[INFO] command: %s\n", command); 
        debug_print("[INFO] arg1: %s\n", arg1);              
        debug_print("[INFO] arg2: %s\n", arg2);
        
        if (strcmp(command, "set_hid_enable") == 0) {
            
            if (i2c_open(arg1) < 0) {
                
                printf("[ERROR] %s is not a valid i2c-dev filenode\n", arg1);
                close(device_fd);
                return (EXIT_FAILURE);
            }
            
            int enable = (strcmp(arg2, "0") == 0) ? 0 : 1;
            
            if (set_hid_enable(enable) < 0) {
                
                printf("[ERROR] could not set_hid_enable\n");
                close(device_fd);
                return (EXIT_FAILURE);
            }
            
            printf("[INFO] hid enable set to %d\n", enable);
            
            close(device_fd);
            
            return (EXIT_SUCCESS);
        }
            
        
        if (strcmp(command, "flash_program") == 0) {
            
            if (i2c_open(arg1) < 0) {
                
                printf("[ERROR] %s is not a valid i2c-dev filenode\n", arg1);
                close(device_fd);
                return (EXIT_FAILURE);
            }
            
            firmware_file file;
            
            if (parse_ftb_file(arg2, &file) < 0) {
                
                debug_print("[ERROR] could not get ftb file info\n");
                close(device_fd);
                return (EXIT_FAILURE);
            }
            
            for (int i = 0; i < FW_UPDATE_MAX_RETRY; i++) {
                
                debug_print("[INFO] attempting fw update, retry %d / %d...\n", (i+1), FW_UPDATE_MAX_RETRY);
                
                int ret = flash_burn(&file, 1, 1);
                
                if (ret == 0) {
                                                            
                    close(device_fd);
            
                    free(file.fw_data);
                    free(file.config_data);
                    free(file.cx_data);                                        
                    
                    printf("[INFO] fw update completed successfully\n");
                    
                    return (EXIT_SUCCESS);                    
                } else {
                    
                   debug_print("[WARNING] fw update failed\n"); 
                }
            }
                                        
            printf("[ERROR] could not perform FW update after %d attempts\n", FW_UPDATE_MAX_RETRY);                
                        
            close(device_fd);
            
            free(file.fw_data);
            free(file.config_data);
            free(file.cx_data);
            
            close(device_fd);
            return (EXIT_FAILURE);            
        }
    }
    
    
    print_usage();    
    return (EXIT_SUCCESS);        
}

