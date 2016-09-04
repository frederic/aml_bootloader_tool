/**
 * aml_bootloader_tool - Amlogic S905 bootloader tool
 * https://github.com/frederic/aml_bootloader_tool
 * $ gcc -o aml_bootloader_tool -ltomcrypt aml_bootloader_tool.c
 **/

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <tomcrypt.h>

#define TOC_OFFSET 0xC000
#define TOC_HEADER_NAME	0xAA640001
#define TOC_ENTRY_COUNT_MAX 32
#define SHA256_LEN	32

typedef struct __attribute__((__packed__)) {
	unsigned char   __u_bits[16];
} uuid_t;

typedef struct __attribute__((__packed__)) fip_toc_entry {
	uuid_t		uuid;
	uint64_t	offset_address;
	uint64_t	size;
	uint64_t	flags;
} fip_toc_entry_t;

typedef struct __attribute__((__packed__)) fip_toc_header {
	uint32_t	name;
	uint32_t	serial_number;
	uint64_t	flags;
} fip_toc_header_t;

typedef struct  __attribute__((__packed__)) fip_toc_table {
	fip_toc_header_t header;
	fip_toc_entry_t entries[TOC_ENTRY_COUNT_MAX];
} fip_toc_table_t;


typedef struct __attribute__((__packed__)) aml_img_header {
	unsigned char magic[4];// @AML
	uint32_t total_len;
	uint8_t header_len;
	uint8_t unk_x9;
	uint8_t unk_xA;
	uint8_t unk_xB;
	uint32_t unk_xC;
	uint32_t sig_type;
	uint32_t sig_offset;
	uint32_t sig_len;
	uint32_t data_offset;
	uint32_t unk_x20;
	uint32_t cert_offset;
	uint32_t cert_len;
	uint32_t data_len;
	uint32_t unk_x30;
	uint32_t code_offset;
	uint32_t code_len;
	uint32_t unk_x3C;
} aml_img_header_t;

enum SIG_TYPE{
	SIG_SHA256 = 0,
	SIG_RSA1024,
	SIG_RSA2048,
	SIG_RSA4096
};

void printArray(unsigned char buf[], unsigned int n) {
	int i;
	for (i = 0; i < n; i++)
	{
		printf("%02X", buf[i]);
	}
	printf("\n");
}

void hash_aml_img(aml_img_header_t *h, unsigned char *hash){
	unsigned char *img_ptr = (unsigned char*) h;
	hash_state md;
	
	register_hash(&sha256_desc);
	sha256_init(&md);
	uint32_t w21 = (0x40 - (h->cert_len & 0x3f));
	memcpy(img_ptr + h->sig_offset, img_ptr + h->code_len + w21, h->code_offset - w21);
	sha256_process(&md, img_ptr, h->header_len);
	sha256_process(&md, (img_ptr + h->code_len), h->cert_len + w21);
	sha256_process(&md, img_ptr + w21, h->code_len - w21);
	sha256_done(&md, hash);
}

void parse_aml_img_header(aml_img_header_t *h, int overwrite_sha256){
	printf("magic[@0x0]:\t\t%.4s\n", h->magic);
	printf("total_len[@0x4]:\t0x%x\n", h->total_len);
	printf("header_len[@0x8]:\t0x%x\n", h->header_len);
	printf("unk_xC[@0xC]:\t\t0x%x\n", h->unk_xC);
	printf("sig_type[@0x10]:\t0x%x\n", h->sig_type);
	printf("sig_offset[@0x14]:\t0x%x\n", h->sig_offset);
	printf("sig_len[@0x18]:\t\t0x%x\n", h->sig_len);
	printf("data_offset[@0x1c]:\t0x%x\n", h->data_offset);
	printf("unk_x20[@0x20]:\t\t0x%x\n", h->unk_x20);
	printf("cert_offset[@0x24]:\t0x%x\n", h->cert_offset);
	printf("cert_len:\t\t0x%x\n", h->cert_len);
	printf("data_len:\t\t0x%x\n", h->data_len);
	printf("unk_x30[@0x30]:\t\t0x%x\n", h->unk_x30);
	printf("code_offset[@0x34]:\t0x%x\n", h->code_offset);
	printf("code_len[@0x38]:\t0x%x\n", h->code_len);
	printf("unk_x3C[@0x3C]:\t\t0x%x\n", h->unk_x3C);
	printf("signature:\t\t");
	printArray((unsigned char*)h + h->sig_offset, h->sig_len); //BUG potential overflow/overread
	
	if(overwrite_sha256 >= 0){
		h->sig_type = SIG_SHA256;
		h->sig_len = SHA256_LEN;
	}
	
	if(h->sig_type == SIG_SHA256){
		hash_aml_img(h, (unsigned char*)h + h->sig_offset);
		printf("computed_sha256:\t");
		printArray((unsigned char*)h + h->sig_offset, SHA256_LEN);
	}
	printf("\n");
}

void parse_aml_img_toc(unsigned char *buf, size_t buf_size, int overwrite_sha256){
	fip_toc_table_t* t = (fip_toc_table_t*)(buf + TOC_OFFSET);
	uuid_t uuid_null = {{0}};
	int i;
	printf("fip_toc_header.name:\t\t%x\n", t->header.name);
	printf("fip_toc_header.serial_number:\t\t%x\n", t->header.serial_number);
	printf("fip_toc_header.flags:\t\t%lx\n", t->header.flags);
	
	for(i = 0; i < TOC_ENTRY_COUNT_MAX; i++){
		if(!memcmp(&t->entries[i].uuid, &uuid_null, sizeof(uuid_null)))
			break;
		
		if (overwrite_sha256 >= 0 && overwrite_sha256 != i)
			continue;
		
		printf("TOC ENTRY #%u\n", i);
		printf("fip_toc_entry.uuid:\t\t");
		printArray((unsigned char*)&t->entries[i].uuid, sizeof(uuid_t));
		printf("fip_toc_entry.offset_address:\t%lx (absolute: 0x%lx)\n", t->entries[i].offset_address, t->entries[i].offset_address + TOC_OFFSET);
		printf("fip_toc_entry.size:\t\t0x%lx\n", t->entries[i].size);
		printf("fip_toc_entry.flags:\t\t0x%lx\n", t->entries[i].flags);
		parse_aml_img_header((aml_img_header_t *)(buf + t->entries[i].offset_address + TOC_OFFSET), overwrite_sha256);
	}
}

int main(int argc, char *argv[])
{
	FILE *fd;
	unsigned char *buf_in;
	size_t fd_size, result;
	int overwrite_sha256 = -1;
	
	if (argc == 4 && argv[2][0] == 'H') { //YOLOL
		overwrite_sha256 = atoi(argv[3]);
	}else if (argc != 2) {
		printf("Usage: %s <bootloader_partition_dump> [H <index>]\n", argv[0]);
		printf("\tH <index>: regenerate hash for specified TOC ENTRY and write in place\n");
		exit(-1);
	}
	
	fd = fopen(argv[1],"rb+");
	if (fd == NULL) {
		perror("Can't open input file !\n");
		exit(-1);
	}
	
    fseek (fd, 0, SEEK_END);
	fd_size = ftell(fd);
	if (fd_size < sizeof(fip_toc_table_t)) {
		printf("Error: input file too small to read header!\n");
		exit(-1);
	}
	
	buf_in = (unsigned char*) malloc(fd_size);
	if(!buf_in){
		printf("Error: cannot allocate input buffer !\n");
		exit(-1);
	}
	
	fseek (fd, 0, SEEK_SET);
	result = fread(buf_in, 1, fd_size, fd);
	if (result != fd_size) {
		printf("Error: cannot read entire file !\n");
		exit(-1);
	}
	
	parse_aml_img_toc(buf_in, fd_size, overwrite_sha256);
	
	if (overwrite_sha256 >= 0){
		fseek(fd, 0, SEEK_SET);
		fwrite(buf_in, 1, fd_size, fd);
	}
	
	fclose(fd);
	return 0;
}
