

// Malloc program

// API: 

// 

// Data layout

enum policy {
    first_fit = 0,
    best_fit = 1,
}

void* head, tail;

// Structure of free list

// -------
// prev_size | occupied bit

// -------
// -------
// -------
// MEMORY START
// -------

// -------

// MEMORY END
// 

// unfortunately this algorithm is both O(n) allocation and O(n) for deletion worst case

void *list_head, *list_tail;
size_t largest_chunk;

#define WORD_SIZE sizeof(size_t)
#define HEADER_OVERHEAD 2*WORD_SIZE
#define FREE_CHUNK_UNDERHEAD 2*WORD_SIZE

#define MIN_SIZE (HEADER_OVERHEAD + FREE_CHUNK_UNDERHEAD)

// conventions
// whenever we refer to a chunk, we refer to the first byte of the actual memory region.

// functions needed 

// set the occupied bit of a chunk (by looking at the next chunk)
// #define set_occupied_previous(addr, bit_value) 
void set_occupied_previous(void* address, bool bit) {
    
}

// get actual memory size of a chunk


// given a free block, merge it with its neighbors


// get the location of the next chunk given the current chunk's data


// get the location of the next free chunk


// get the location 

// 

void *find_available_chunk(size_t size) {

}

void *extend_heap(size_t size) {
    
}

void free_chunk(void* location) {

}

void occupy_chunk(void* chunk) {

}

void *ff_malloc(size_t size);

void ff_free(void *location);

void *bf_malloc(size_t size);

void bf_free(void *location);

