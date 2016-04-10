/**
 *    genfw.c
 *    Generate loadable firmware for NL6611
 *    Copyright 2016 Tido Klaassen <tido@4gh.eu>
 *
 *    This file is part of the NL6621 Tools.
 *
 *    NL6621 Tools are free software: you can redistribute it and/or modify
 *    it under the terms of the GNU General Public License as published by
 *    the Free Software Foundation, either version 3 of the License, or
 *    (at your option) any later version.
 *
 *    Foobar is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    GNU General Public License for more details.
 *
 *    You should have received a copy of the GNU General Public License
 *    along with Foobar.  If not, see <http://www.gnu.org/licenses/>.
 **/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <endian.h>
#include <getopt.h>
#include <time.h>
#include <errno.h>
#include <libgen.h>

enum chksum_type {
    chksum_none = 0x0,
    chksum_crc32 = 0x1,
    chksum_crc8 = 0x2,
};

typedef uint32_t (*chksum_func)(uint32_t crc, const uint8_t *data, size_t len);

#define HDR_SIZE        0x100U
#define I2C_SPD_NORM    0x0U
#define I2C_SPD_HIGH    0x1U

#define DEF_ENTRY_ADDR  0x00010100U
#define DEF_CHKSUM      chksum_crc32
#define DEF_BURSTLEN    2048U
#define DEF_I2C_SPD     I2C_SPD_HIGH
#define DEF_SPI_CLKDIV  384U
#define DEF_UART_RATE   115200U

struct _fw_hdr {
    uint8_t magic[8];     // Nu_link
    uint32_t fw_size;     // total firmware image len, including fw hdr and tail
    uint32_t fw_version;  // either UNIX time stamp or one byte each for 
                          // Major, Minor, Patch and Build.
    uint32_t entry_addr;  //
    uint16_t chksum_type; //check flag, b1..0 , 0 not check 1: CRC, 2: SUM8
    uint16_t burst_len;   // default 2K for SDIO, must be multiple of 4 bytes
    uint16_t i2c_speed;   // 0: standard mode, 1: fast mode
    uint16_t spi_clk_div; // SPI clk div, SPI_CLK=40MHZ/clk_div
    uint32_t uart_rate;   // UART baudrate
} __attribute__((packed));

typedef struct _fw_hdr fw_hdr;

struct _fw_tail {
    uint32_t chksum;
    uint8_t magic[8]; // 'D', 'E', 'A', 'D', 'B', 'E', 'E', 'F
} __attribute__((packed));

typedef struct _fw_tail fw_tail;

uint32_t parse_version(char *str)
{
    int result;
    uint32_t version, major, minor, patch, build;
    char *end;

    version = 0;
    result = sscanf(str, "%u:%u:%u:%u", &major, &minor, &patch, &build);
    if(result == 4){
        version |= ((major & 0xff) << 24); 
        version |= ((minor & 0xff) << 16); 
        version |= ((patch & 0xff) <<  8); 
        version |= ((build & 0xff) <<  0);
    } else {
        errno = 0;
        end = str;
        version = strtoul(str, &end, 0);
        if(errno != 0 || *end != '\0'){
            fprintf(stderr, "Error parsing version string\n");
            exit(1);
        }
    }

    return version;
}

/**
 * CRC32 look-up table computed for polynomial 0xedb88320
 */ 
const uint32_t crc32_table[] = {
    0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, 0x076dc419, 0x706af48f, 
    0xe963a535, 0x9e6495a3, 0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988, 
    0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91, 0x1db71064, 0x6ab020f2, 
    0xf3b97148, 0x84be41de, 0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7, 
    0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec, 0x14015c4f, 0x63066cd9, 
    0xfa0f3d63, 0x8d080df5, 0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172, 
    0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b, 0x35b5a8fa, 0x42b2986c, 
    0xdbbbc9d6, 0xacbcf940, 0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59, 
    0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116, 0x21b4f4b5, 0x56b3c423, 
    0xcfba9599, 0xb8bda50f, 0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924, 
    0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d, 0x76dc4190, 0x01db7106, 
    0x98d220bc, 0xefd5102a, 0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433, 
    0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818, 0x7f6a0dbb, 0x086d3d2d, 
    0x91646c97, 0xe6635c01, 0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e, 
    0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457, 0x65b0d9c6, 0x12b7e950, 
    0x8bbeb8ea, 0xfcb9887c, 0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65, 
    0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2, 0x4adfa541, 0x3dd895d7, 
    0xa4d1c46d, 0xd3d6f4fb, 0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0, 
    0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9, 0x5005713c, 0x270241aa, 
    0xbe0b1010, 0xc90c2086, 0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f, 
    0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4, 0x59b33d17, 0x2eb40d81, 
    0xb7bd5c3b, 0xc0ba6cad, 0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a, 
    0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683, 0xe3630b12, 0x94643b84, 
    0x0d6d6a3e, 0x7a6a5aa8, 0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1, 
    0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe, 0xf762575d, 0x806567cb, 
    0x196c3671, 0x6e6b06e7, 0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc, 
    0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5, 0xd6d6a3e8, 0xa1d1937e, 
    0x38d8c2c4, 0x4fdff252, 0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b, 
    0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60, 0xdf60efc3, 0xa867df55, 
    0x316e8eef, 0x4669be79, 0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236, 
    0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f, 0xc5ba3bbe, 0xb2bd0b28, 
    0x2bb45a92, 0x5cb36a04, 0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d, 
    0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a, 0x9c0906a9, 0xeb0e363f, 
    0x72076785, 0x05005713, 0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38, 
    0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21, 0x86d3d2d4, 0xf1d4e242, 
    0x68ddb3f8, 0x1fda836e, 0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777, 
    0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c, 0x8f659eff, 0xf862ae69, 
    0x616bffd3, 0x166ccf45, 0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2, 
    0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db, 0xaed16a4a, 0xd9d65adc, 
    0x40df0b66, 0x37d83bf0, 0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9, 
    0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6, 0xbad03605, 0xcdd70693, 
    0x54de5729, 0x23d967bf, 0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94, 
    0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d, 
};

uint32_t calc_crc32(uint32_t crc, const uint8_t *data, size_t len)
{
    crc ^= 0xffffffffU;

    while(len > 0){
        crc = crc32_table[(crc ^ *data) & 0xff] ^ (crc >> 8);
        ++data;
        --len;
    }

    crc ^= 0xffffffffU;

    return crc;
}

uint32_t calc_none(uint32_t crc, 
                    const uint8_t *data __attribute__((unused)), 
                    size_t len __attribute__((unused)))
{
    return crc;
}

void usage(const char *path)
{
    char *me;

    me = strdup(path);

    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "%s "
                    "[-v {version|major:minor:patch:build}] "
                    "[-e {entry addr}] "
                    "[-b {burst len}] "
                    "[-i {normal|high}] "
                    "[-c {SPI clock divisor}] "
                    "[-u {UART baud rate}] "
                    "[-s {crc32|none}] " /* crc8 not supported yet */
                    "[-d] "
                    "infile [outfile]"
                    "\n", 
                basename(me));

    fprintf(stderr, "  -v: set firmware version\n");
    
    fprintf(stderr, "      supply either a valid integer or "
                    " major, minor, patch level and build\n");

    fprintf(stderr, "      number separated by colons. Defaults to "
                    "current UNIX timestamp\n");

    fprintf(stderr, "  -e: set firmware entry address\n");

    fprintf(stderr, "  -b: set SDIO burst length. Defaults to %d\n", 
                DEF_BURSTLEN);

    fprintf(stderr, "  -i: set I2C speed. Defaults to %s\n", 
                DEF_I2C_SPD == I2C_SPD_HIGH ? "high" : "normal");

    fprintf(stderr, "  -c: set SPI clock devisor. Defaults to %d\n", 
                DEF_SPI_CLKDIV);

    fprintf(stderr, "  -u: set UART baud rate. Defaults to %d\n", 
                DEF_UART_RATE);

    fprintf(stderr, "  -s: set checksum type. Defaults to %s \n", 
                DEF_CHKSUM == chksum_crc32 ? "crc32" :
                /* DEF_CHKSUM == chksum_crc8  ? "crc8"  : */
                DEF_CHKSUM == chksum_none ?  "none"  :
                                             "unknown?!");

    fprintf(stderr, "  -d: discard existing firmware header\n");

    fprintf(stderr, "  infile: path to input file\n");
    fprintf(stderr, "  outfile: path to write firmware image to. Defaults to \'-\' (stdout)\n");
}

int main(int argc, char **argv)
{
    int opt, result;
    unsigned int optval;
    char *input_path, *output_path;
    int in_fd, out_fd;
    fw_hdr hdr;
    fw_tail tail;
    struct stat stat_buf;
    off_t seek;
    uint8_t data_buf[HDR_SIZE];
    size_t bin_size, written;
    ssize_t read_len;
    enum chksum_type crc_type;
    chksum_func crc_func;
    bool with_hdr;
    uint32_t crc;

    in_fd = -1;
    out_fd = -1;
    crc_type = DEF_CHKSUM;
    with_hdr = false;

    /**
     * initialise header with default values
     */
    memcpy(&hdr.magic, "Nu_link", sizeof(hdr.magic));
    hdr.fw_version = htole32(time(NULL));
    hdr.entry_addr = htole32(DEF_ENTRY_ADDR);
    hdr.burst_len = htole16(DEF_BURSTLEN);
    hdr.i2c_speed = htole16(DEF_I2C_SPD);
    hdr.spi_clk_div = htole16(DEF_SPI_CLKDIV);
    hdr.uart_rate = htole32(DEF_UART_RATE);

    while((opt = getopt(argc, argv, "v:e:b:i:c:u:s:d")) != -1){
        errno = 0;
        switch (opt) {
        case 'v':
            hdr.fw_version = parse_version(optarg);
            break;
        case 'e':
            optval = strtoul(optarg, NULL, 0);
            if(optval == 0 && errno != 0){
                fprintf(stderr, "Error parsing entry address\n");
                goto err_out;
            }
            hdr.entry_addr = htole32(optval);
            break;
        case 'b':
            optval = strtoul(optarg, NULL, 0);
            if(optval == 0 && errno != 0){
                fprintf(stderr, "Error parsing burst length\n");
                goto err_out;
            }
            hdr.burst_len = htole16(optval);
            break;
        case 'i':
            optval = strtoul(optarg, NULL, 0);
            if(optval == 0 && errno != 0){
                fprintf(stderr, "Error parsing I2C speed\n");
                goto err_out;
            }
            hdr.i2c_speed = htole16(optval);
            break;
        case 'c':
            optval = strtoul(optarg, NULL, 0);
            if(optval == 0 && errno != 0){
                fprintf(stderr, "Error parsing SPI clock divider\n");
                goto err_out;
            }
            hdr.spi_clk_div = htole16(optval);
            break;
        case 'u':
            optval = strtoul(optarg, NULL, 0);
            if(optval == 0 && errno != 0){
                fprintf(stderr, "Error parsing uart rate\n");
                goto err_out;
            }
            hdr.uart_rate = htole32(optval);
            break;
        case 's':
            if(!strcmp(optarg, "crc32")){
                crc_type = chksum_crc32;
            /* CRC8 parameters are unknown, so not supported yet */
#if 0
            } else if(!strcmp(optarg, "crc8")){
                crc_type = chksum_crc8;
#endif
            } else if(!strcmp(optarg, "none")){
                crc_type = chksum_none;
            } else {
                fprintf(stderr, "invalid checksum type: %s\n", optarg);
                goto err_out;
            }
            break;
        case 'd':
            with_hdr = true;
            break;
        default: /* '?' */
            usage(argv[0]);
            goto err_out;
        }
    }
    
    hdr.chksum_type = htole16(crc_type);

    switch(crc_type){
    case chksum_crc32:
        crc_func = calc_crc32;
        break;
    case chksum_crc8:
#if 0
        crc_func = calc_crc8;
#endif
        break;
    case chksum_none:
        crc_func = calc_none;
        break;
    }

    if(optind >= argc){
        fprintf(stderr, "input file missing\n");
        usage(argv[0]);
        goto err_out;
    }

    input_path = argv[optind];
    output_path = "-";

    ++optind;
    if(optind < argc){
        output_path = argv[optind];
    }

    in_fd = open(input_path, O_RDONLY);
    if(in_fd < 0){
        fprintf(stderr, "Error opening input file %s: %s\n", 
                    input_path, strerror(errno));
        goto err_out;
    }

    result = fstat(in_fd, &stat_buf);
    if(result != 0){
        fprintf(stderr, "Error getting attributes of input file %s: %s\n", 
                    input_path, strerror(errno));
        goto err_out;
    }
    
    if(!S_ISREG(stat_buf.st_mode)){
        fprintf(stderr, "Firmware image needs to be a regular file.\n");
        goto err_out;
    }

    /**
     * The vector table starts at offset 0x100. The first 256 bytes in a 
     * firmware image are used by the header and filled up with zeroes.
     * We have to add these to the binary's length, unless the -d switch is
     * given, indicating that there is already a header present that must be
     * discarded.
     */ 
    bin_size = stat_buf.st_size;
    if(with_hdr){
       /**
        * start of input file is replaced with our firmware header, so we
        * skip the first HDR_SIZE bytes.
        */
       seek = lseek(in_fd, HDR_SIZE, SEEK_SET);
       if(seek < 0){
           fprintf(stderr, "lseek() failed on input file: %s\n", 
                       strerror(errno));

           goto err_out;
       }

       bin_size -= HDR_SIZE;
    }

    /* Set final firmware length */
    hdr.fw_size = htole32(bin_size + HDR_SIZE + sizeof(tail));

    /**
     * Header data is complete. Open output file.
     */
    
    if(!strcmp(output_path, "-")){
        out_fd = dup(STDOUT_FILENO);
    } else {
        out_fd = open(output_path, O_WRONLY | O_CREAT | O_TRUNC, 
                                  S_IRUSR | S_IWUSR);
    }

    if(out_fd < 0){
        fprintf(stderr, "Error opening output file %s: %s\n", 
                    output_path, strerror(errno));
        goto err_out;
    }

    /**
     * Copy the header data into the data buffer, start calculating CRC 
     * and write header to output file.
     */
    memset(&(data_buf[0]), 0x0, HDR_SIZE);
    memmove(&(data_buf[0]), &hdr, sizeof(hdr));
    crc = (*crc_func)(0, &(data_buf[0]), HDR_SIZE);

    written = 0;
    do{
        result = write(out_fd, &(data_buf[written]), HDR_SIZE - written);
        if(result < 0){
            fprintf(stderr, "Error writing output file: %s\n", strerror(errno));
            goto err_out;
        }

        written += result;
    }while(written < HDR_SIZE);


    /**
     * Read binary from input file, update CRC and copy it to the output file.
     */
    do{
        read_len = read(in_fd, &(data_buf[0]), sizeof(data_buf));
        if(read_len < 0){
            fprintf(stderr, "Error reading input file: %s\n", strerror(errno));
            goto err_out;
        }

        crc = (*crc_func)(crc, &(data_buf[0]), read_len);

        written = 0;
        while(read_len - written > 0){
            result = write(out_fd, &(data_buf[written]), read_len - written);
            if(result < 0){
                fprintf(stderr, "Error writing output file: %s\n", 
                            strerror(errno));
                goto err_out;
            }

            written += result;
        };
    }while(read_len > 0);
   
    /**
     * Copy calculated CRC and magic string into tail data struct and
     * write it to the output file
     */ 
    tail.chksum = htole32(crc);
    tail.magic[0] = 'D';
    tail.magic[1] = 'E';
    tail.magic[2] = 'A';
    tail.magic[3] = 'D';
    tail.magic[4] = 'B';
    tail.magic[5] = 'E';
    tail.magic[6] = 'E';
    tail.magic[7] = 'F';
    
    written = 0;
    do{
        result = write(out_fd, &tail + written, sizeof(tail) - written);
        if(result < 0){
            fprintf(stderr, "Error writing output file: %s\n", strerror(errno));
            goto err_out;
        }

        written += result;
    }while(written < sizeof(tail));

    /**
     * We are done. Clean up and exit.
     */
    close(in_fd);
    close(out_fd);

    exit(EXIT_SUCCESS);

err_out:
    if(in_fd >= 0){
        close(in_fd);
    }

    if(out_fd >= 0){
        close(out_fd);
    }

    exit(EXIT_FAILURE);
}
