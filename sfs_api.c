// Josh Liu ID 260612384

#include "sfs_api.h"
#include "disk_emu.h"
#include <strings.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <regex.h>
#include <math.h>

#define DISK_FILE "sfs_disk.disk"
#define BLOCK_SIZE 512
#define MAX_BLOCKS 300

#define MAX_INODES 111
#define MAX_FILES 110

// valid name regex
#define REGEXDOT "(^[a-z0-9A-Z]{1,16})(\\.)([a-zA-Z0-9]{1,3})$" 
#define REGEX "^[a-z0-9A-Z]{1,16}$"

super_block_t sb;
dir_entry_t root_dir[MAX_FILES];
char buff [BLOCK_SIZE];
inode_t inode_table[MAX_INODES];
fd_table_t fd_table[MAX_FILES];
unsigned short free_blocks[MAX_BLOCKS];
int namecounter = 0;

void init_superblock() {

        sb.magic = 1234;
        sb.block_size = BLOCK_SIZE;
        sb.fs_size = MAX_BLOCKS*BLOCK_SIZE;
        sb.inode_table_len = MAX_INODES;
        sb.root_dir_inode = 0;
}

void add_root_dir_inode() {

        //  root node is stored in the inode table
        inode_table[0].mode =  0x755;
        inode_table[0].link_cnt = 1;
        inode_table[0].uid = 0;
        inode_table[0].gid = 0;
        inode_table[0].size = 103;
	//root dir is stored in block 17
        inode_table[0].data_ptrs[0] = 17; 
}

void zero_everything() {

        bzero(&sb, sizeof(super_block_t));
        bzero(&fd_table[0], sizeof(fd_table_t)*MAX_FILES);
        bzero(&inode_table[0], sizeof(inode_t)*MAX_INODES);
        bzero(&root_dir, sizeof(dir_entry_t)*MAX_INODES);
        bzero(&free_blocks[0], sizeof(unsigned int)*MAX_BLOCKS);
	bzero(&buff[0], BLOCK_SIZE);
}

// Removes ^A from a string which was giving an error from strpy
void removeCtrlA(char *name) {
	int i;
	for (i = 0; i <= MAXFILENAME; i++) if (name[i] == 1) name[i] = '\0';

}

// Checks if the filename is valid
int valid_name(char *file, int period) {

  	regex_t regex;
  	int r;
  	char buf[100];
  	
	if (strlen(file) > MAXFILENAME) return 100;

	// does it have an extension?
  	if(period == 1) { 
  		
		// makes regex
  		r = regcomp(&regex, REGEXDOT, REG_EXTENDED);
  		if (r) {
    			printf("Regex compile error");
    			return -1;
  		}

  		// checks for match
  		regexec(&regex, file, 0, NULL, 0);
  		if (r == REG_NOMATCH) {
    			printf("'%s' Invalid name\n", file);
    			return -1;
  		}
		else if (r) {
    			regerror(r, &regex, buf, sizeof(buf));
    			fprintf(stderr, "error %s\n", buf);
    			return -1;
  		}
  		regfree(&regex);
  		return r;
  	}
  	else {
  		r = regcomp(&regex, REGEX, REG_EXTENDED);
  		if (r) {
    			printf("Regex compile error");
    			return -1;
  		}

  		regexec(&regex, file, 0, NULL, 0);
  		if (r == REG_NOMATCH) {
    			printf("'%s' Invalid name\n", file);
    			return -1;
  		}
  
		else if (r) {
    			regerror(r, &regex, buf, sizeof(buf));
    			fprintf(stderr, "error %s\n", buf);
    			return -1;
  		}
  		regfree(&regex);
  		return r;	
	}

}

void mksfs(int fresh) {

	//Implement mksfs here	
	if (fresh == 1) {

                printf("Initalizing sfs\n");
		init_fresh_disk(DISK_FILE, BLOCK_SIZE, MAX_BLOCKS);
                zero_everything();

		// write superblock to the first block
                printf("Writing superblocks\n");
                init_superblock();
		write_blocks(0, 1, &sb);
	
		// write the inode table to the 2nd block
                printf("Writing inode table\n");
                add_root_dir_inode();
		write_blocks(1, 16, &inode_table);

                // write root directory data to the 17th block
                printf("Writing root dir\n");
                write_blocks(17,6, &root_dir);

                // mark free blocks as used (at the end of the disk)
                printf("Writing free blocks\n");
		int i;
		for (i = 0; i <= 23; i++) free_blocks[i] = 1;

		free_blocks[MAX_BLOCKS - 1] = 1;
		write_blocks(MAX_BLOCKS - 1, 1, &free_blocks);

	} else {

		init_disk(DISK_FILE, BLOCK_SIZE, MAX_BLOCKS);
	}
}
  
// gets the next filename of the root directory
int sfs_get_next_filename(char *fname) {
 
	int  i;
	if (namecounter == 0) {
		if (strcmp(fname, "\0")) {
			for (i = 0; i < MAX_FILES ; i++) {
				if (root_dir[i].name != NULL) {
					strcpy(fname, root_dir[i].name);
					namecounter = 1;
					return 1;
				}	
		
			}

		}
		namecounter = 1;
	}
	int j;
	for (i = 0; i < MAX_FILES ; i++) {
	
		if (strcmp(fname,root_dir[i].name) == 0){
			for (j = i + 1; j < MAX_FILES - i ; j++){
				if (root_dir[j].name != NULL){
				strcpy(fname, root_dir[j].name);
				printf("%s\n", fname);
				return 1;
				}
			}
		}	
	}
	return 0;

}

// gets filesize given the inode index (searches all attached nodes)
int get_file_size_index(int index) {
	
	int sum = 0;
	while (inode_table[index].backwards_indirect_ptr != NULL) index = inode_table[index].backwards_indirect_ptr;
	sum += inode_table[index].size;
	while (inode_table[index].indirect_ptr != NULL) {
		if(index > 109)break;
		sum += inode_table[inode_table[index].indirect_ptr].size;
		index = inode_table[index].indirect_ptr;
	}
	return sum;
}
 
// gets size of file given a name
int sfs_GetFileSize(const char* path) {

	int i = 0;
	int index, size;
	// find path in root dir copy inode for file and get size.
	while(i < MAX_FILES) {
		if (strcmp(root_dir[i].name, path) == 0) {
			index = root_dir[i].inode_idx;
			size = get_file_size_index(index);
			return size;
		}
		i++;
	}	
 	return -1;
}

// gets an available block and closes the slot in the freeblock array
int get_free_block() {
	
	int i;
	for (i = 0; i < MAX_BLOCKS; i++) {
		if (free_blocks[i] == 0) {
			free_blocks[i] = 1;
			return i;
		}
	}
	return -1;
}

// gets an available inode and puts it in the inode table
int get_free_inode() {

	int i;
	for (i = 0; i < MAX_INODES; i++) {
		if (inode_table[i].mode == NULL) {
      			//new inode for indirect ptr
      			inode_table[i].mode =  0x755;
      			inode_table[i].link_cnt = 1;
      			inode_table[i].uid = 0;
      			inode_table[i].gid = 0;				
			return i;
		}
	}
	return -1;
}

// Opens a file (puts it in the fd table)
int sfs_fopen(char *name) {

	int a, b, size, root_loc, fd_index, index;
	int  exists = 0;

	// Check to see if the file exists
	for(a = 0; a < MAX_FILES; a++) {
		if(strcmp(root_dir[a].name, name) == 0) {
			exists = 1; 
			root_loc = a;	
			break;
		}  
	}

	if (exists == 0) {
		
		int i;
		int period = 0;
		
		// check for valid name
		for(i = 0; i < 20; i++) {
			if(name[i] == '.'){
				period = 1;
			}
		}		
		if (valid_name(name, period) != 0){
			printf("Invalid name \n");
			return -1;
		}
	
		// get an open block for the file
		int open_block = get_free_block();
		if (open_block == -1) {
			printf("No open blocks");
			exit(0);
		}

		int j,k,l;

		// Find space for inode and insert block
		for (j = 0; j < MAX_INODES; j++) {
			if(inode_table[j].mode == NULL) {
				// initialize node
				index = j;
				inode_table[j].mode =  0x755;
        			inode_table[j].link_cnt = 1;
        			inode_table[j].uid = 0;
        			inode_table[j].gid = 0;
        			inode_table[j].size = 0;
        			inode_table[j].data_ptrs[0] = open_block; 
				break;
			}
		}

		// put inode in root directory
		for (k = 0; k < MAX_INODES; k++) {
			if (strcmp(root_dir[k].name, "") == 0) {
				strcpy(root_dir[k].name, name);
				removeCtrlA(root_dir[k].name);
				//striplast(root_dir[k].name);
				root_dir[k].inode_idx = index;
				break;
			}
		}
		
		// Open the file by placing it in the fd_table
		for(l = 0; l < MAX_FILES; l++) {
			if(fd_table[l].inode_idx == NULL){
				fd_index = l;
				fd_table[l].inode_idx = index;
				fd_table[l].rd_write_ptr = 0;
				break;
			}	
		}
		// the position in the fd table
		return fd_index;
	}
	// File exists
	if (exists == 1) { 
		// put file in fd table
		index = root_dir[root_loc].inode_idx;
		for (b = 0; b < MAX_FILES; b++) {
			// checks if it is already there
			if (fd_table[b].inode_idx == index) return b;
			else if (fd_table[b].inode_idx == NULL) {
				fd_table[b].inode_idx = index;
				// set r/w pointer to EOF
				fd_table[b].rd_write_ptr = get_file_size_index(index);
				return b;
			}
		}		
		return fd_index;
	}	

}

// Close a file by removing it from the fd table
int sfs_fclose(int fileID){

	//remove from fd_table
	if (fd_table[fileID].inode_idx != NULL) {
		fd_table[fileID].inode_idx = NULL;
		fd_table[fileID].rd_write_ptr = NULL;
		return 0;
	} 	
	return 1;
}

// read a number of characters (length) from the given file into buf
int sfs_fread(int fileID, char *buf, int length) {

	//Implement sfs_fread here	
	if (length < 0 | fd_table[fileID].inode_idx == NULL) return 0; 

        int index = fd_table[fileID].inode_idx;
        int cur_pos = fd_table[fileID].rd_write_ptr;
        char buffer[BLOCK_SIZE];
	int readlength = 0;
	int offset = 0;
	int bytes_to_read;
	
        inode_t node;
        
	int start_block = (int) cur_pos/BLOCK_SIZE;
	int start_position = cur_pos % BLOCK_SIZE;

        // stops at end of the file
        if (cur_pos + length > get_file_size_index(index)) {
		readlength = get_file_size_index(index) - cur_pos;
	}
	else {
		readlength = length;
	}

	// loop in blocks of 512 bytes, saving in the buffer incrementally
	while (readlength > 0) {		

		int last = 0;
		int start_node = (int) floor((double)start_block/(double)12); 
		int j;
		for (j = 0; j < start_node; j++) index = node.indirect_ptr;
		start_block = start_block % 12;
		node = inode_table[index];

		if (readlength >= BLOCK_SIZE) {
			bytes_to_read = BLOCK_SIZE - start_position;
		} else {
			// if only 1 block left to fill
			bytes_to_read = readlength;
		}

		read_blocks(node.data_ptrs[start_block], 1, &buffer[0]);
		int i;
		for (i = 0; i < bytes_to_read; i++) {
			buf[offset+i] = buffer[start_position+i];
		}

		offset += bytes_to_read;
		readlength -= bytes_to_read;
		fd_table[fileID].rd_write_ptr += bytes_to_read;
		start_block++;
		start_position = fd_table[fileID].rd_write_ptr % BLOCK_SIZE;

	}
	return offset;
}

// writes length characters into the specified file from buf
int sfs_fwrite(int fileID, const char *buf, int length) {

	//Implement sfs_fwrite here
	
	if (length == 0 | fileID < 0 | fileID >= MAX_FILES | fd_table[fileID].inode_idx == NULL) return 0;

	int index = fd_table[fileID].inode_idx;
	int current_ptr_index = (int) floor((double)fd_table[fileID].rd_write_ptr/(double)BLOCK_SIZE);
	int final_block = (int) ceil((double)(fd_table[fileID].rd_write_ptr+length)/(double)BLOCK_SIZE);
	int create_blocks = final_block - current_ptr_index; 
	int current_position = fd_table[fileID].rd_write_ptr % BLOCK_SIZE;
	
	int used_blocks = 0;
	int bufstart = 0;
	int bytes_to_write;
	char buffer[BLOCK_SIZE];

	// write in blocks of 512
	do {	
		// If ptr table runs out create new inode and point to it with indirect pointer
		if (current_ptr_index > 11) {
			int numpointers = (int) current_ptr_index/12;
			int p;
			for (p = 0; p < numpointers; p++) {
				if (inode_table[index].indirect_ptr == NULL) {
					inode_table[index].indirect_ptr = get_free_inode();
					if (inode_table[index].indirect_ptr == -1) {
						printf("NO MORE SPACE\n");
						return -1;
					}
					inode_table[inode_table[index].indirect_ptr].backwards_indirect_ptr = index;
				}
				index = inode_table[index].indirect_ptr;
			}
			current_ptr_index = current_ptr_index % 12;			 
		}

		// If new block is needed
		if (inode_table[index].data_ptrs[current_ptr_index] == NULL) {
			inode_table[index].data_ptrs[current_ptr_index] = get_free_block();
		}	

		if (create_blocks > 1) bytes_to_write = BLOCK_SIZE - current_position;
		else bytes_to_write = length - used_blocks;

		read_blocks(inode_table[index].data_ptrs[current_ptr_index], 1, &buffer[0]);
		int j;
		for (j = 0; j < bytes_to_write; j++) {
			buffer[current_position+j] = buf[bufstart+j]; 
		}

		write_blocks(inode_table[index].data_ptrs[current_ptr_index], 1, &buffer[0]);


		bufstart += bytes_to_write;
		current_position = 0;
		used_blocks += bytes_to_write;
		inode_table[index].size += bytes_to_write;
		fd_table[fileID].rd_write_ptr += bytes_to_write;
		current_ptr_index++;
		create_blocks--;
		
	} while (create_blocks != 0); 
	return used_blocks;
}

// changes the r/w pointer of the file to loc
int sfs_fseek(int fileID, int loc) {
        
        if (loc < 0 | loc > get_file_size_index(fd_table[fileID].inode_idx)) return 0;
        else fd_table[fileID].rd_write_ptr = loc;
	return 1;
}

// removes a file from disk
int sfs_remove(char *file) {
	
	int index, i,j;
	int k = 0;
	int found = 0;

	//clear root dir of file name 
		for (i = 0;i < MAX_INODES; i++){
			if(strcmp(root_dir[i].name,file) == 0){		
				index = root_dir[i].inode_idx;
				int z;
				for (z = 0; z < sizeof(root_dir[i].name); z++) root_dir[i].name[z] = '\0';
				root_dir[i].inode_idx = NULL;
				found = 1;
				break;
			}
		}
	
	//If you can't find the file
	if (found == 0){
		printf("Couldn't find %s, exiting remove method", file);
		return -1;	
	}
	int next_inode;

	do{
		//clear inodes 
		inode_table[index].mode = NULL;
		inode_table[index].link_cnt = NULL;
        	inode_table[index].uid = NULL;
		inode_table[index].gid = NULL;
		inode_table[index].size = NULL;
	
		//Clear inode pointer array
		for (j = 0; j < 12; j++){
			
			if (inode_table[index].data_ptrs[j] != NULL){
				int bl = inode_table[index].data_ptrs[j];
				//write null to a block if used.
				write_blocks(bl,1,buff);
				//set 0 free block array.
				free_blocks[bl] =0;	
				inode_table[index].data_ptrs[j] = NULL;
			}		
		}

		next_inode = inode_table[index].indirect_ptr;
		inode_table[index].indirect_ptr = NULL;
		inode_table[index].backwards_indirect_ptr = NULL;
		index = next_inode;	
	}while(next_inode != NULL);
	
	return 0;
}



