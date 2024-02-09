#include <stdbool.h> 
#include <stdint.h>   
#include <stddef.h>   
#include <unistd.h>  
#include <assert.h>  
#include <string.h>   
#include <stdio.h>   

// #define DEBUG_VERBOSE

#define INIT_SIZE (1 << 20)

#define ERROR -1
#define SUCCESS 0

void *mem_begin, *mem_end;
bool init = false;

// -------------------------------------------------------------
// POINTER ARITHMETIC
#define PTR_LESS_THAN -1
#define PTR_EQUAL 0
#define PTR_GREATER_THAN 1
int ptr_cmp(void *ptr_1, void *ptr_2) {
    uintptr_t addr_1 = (uintptr_t)ptr_1;
    uintptr_t addr_2 = (uintptr_t)ptr_2;

    if (addr_1 < addr_2) {
        return PTR_LESS_THAN;
    } else if (addr_1 > addr_2) {
        return PTR_GREATER_THAN;
    } else {
        return PTR_EQUAL;
    }
}

bool out_of_bounds(void *check) {

    int mem_begin_cmp = ptr_cmp(mem_begin, check);
    bool check_before_mem_begin = mem_begin_cmp == PTR_GREATER_THAN;
    int mem_end_cmp = ptr_cmp(check, mem_end);
    bool check_after_mem_end = mem_end_cmp == PTR_GREATER_THAN;

    return check_before_mem_begin || check_after_mem_end;
}

size_t abs_ptr_diff(void *ptr_1, void *ptr_2) {
    uintptr_t addr_1 = (uintptr_t)ptr_1;
    uintptr_t addr_2 = (uintptr_t)ptr_2;

    return (addr_1 > addr_2) ? (addr_1 - addr_2) : (addr_2 - addr_1);
}

void *add_absolute(void *address, size_t difference) {
    char *addr_char = (char *) address;

    addr_char += difference;
    return (void *) addr_char;
}

void *subtract_absolute(void *address, size_t difference) {
    char *addr_char = (char *) address;

    addr_char -= difference;
    return (void *) addr_char;
}

// -------------------------------------------------------------
// STRUCT DEFINITIONS

#define HEADER_OVERHEAD 16
#define FREE_CHUNK_UNDERHEAD 16
#define MIN_CHUNK_SIZE (HEADER_OVERHEAD + FREE_CHUNK_UNDERHEAD)

struct chunk {
    uint64_t prev_size_and_occupied_bit;
    uint64_t current_size_and_occupied_bit;
    struct chunk *prev_free, *next_free; // this will be occupied when allocating memory
};

typedef struct chunk* chunk_ptr_t;

chunk_ptr_t head, tail;



size_t get_prev_size(chunk_ptr_t current) {
    return current->prev_size_and_occupied_bit>>1;
}

size_t get_size(chunk_ptr_t current) {
    return current->current_size_and_occupied_bit>>1;
}

void tail_sanity_check() {
    void *tail_end = subtract_absolute(add_absolute(tail, HEADER_OVERHEAD + get_size(tail)), 1);
    assert(ptr_cmp(tail_end, mem_end) == PTR_EQUAL);
}

chunk_ptr_t get_prev(chunk_ptr_t current) {

    size_t prev_size = get_prev_size(current);
    if (prev_size == 0) return NULL;

    chunk_ptr_t prev_chunk_addr = (chunk_ptr_t) subtract_absolute(current, HEADER_OVERHEAD + prev_size);
    if (out_of_bounds(prev_chunk_addr))
        return NULL;

    return prev_chunk_addr;
}

chunk_ptr_t get_next(chunk_ptr_t current) {
    size_t current_size = get_size(current);
    if (current_size == 0) 
        return NULL;

    chunk_ptr_t next_chunk_addr = (chunk_ptr_t) add_absolute(current, HEADER_OVERHEAD + current_size);
    if (out_of_bounds(add_absolute(next_chunk_addr, MIN_CHUNK_SIZE-1)))
        return NULL;

    return next_chunk_addr;
}

bool is_free(chunk_ptr_t current) {
    bool occupied = current->current_size_and_occupied_bit & 1;
    return !occupied;
}

bool prev_is_free(chunk_ptr_t current) {
    if (current->prev_size_and_occupied_bit == 0) return false;
    bool prev_occupied = current->prev_size_and_occupied_bit & 1;
    return !prev_occupied;
}

bool next_is_free(chunk_ptr_t current) {
    chunk_ptr_t next = get_next(current);
    if (next == NULL) return false;

    return is_free(next);
}

// size_t debug_count = 0;
// void debug_current_layout() {
//     printf("************************************* %zu\n", ++debug_count);
//     chunk_ptr_t current = head;
//     printf("Mem begin at %p\n", mem_begin);
//     printf("Head at %p\n", (void*)head); // Cast to void* for %p specifier
//     while (current != NULL) {
//         printf("----------Chunk at: %p\n", (void*)current);
//         // Assuming size is stored as the actual size without the occupied bit
//         printf("Previous size: %zu, status: %s\n", get_prev_size(current), (prev_is_free(current) ? "Free" : "Occupied"));
//         printf("Current size: %zu, status: %s\n", get_size(current), (is_free(current) ? "Free" : "Occupied"));
//         if (is_free(current)) {
//             // These casts ensure the pointer is printed correctly
//             printf("Previous free chunk at: %p\n", (void*)current->prev_free);
//             printf("Next free chunk at: %p\n", (void*)current->next_free);
//         }
//         current = get_next(current); // Move to the next chunk in the list
//     }
//     printf("Tail at %p\n", (void*)tail); // Cast to void* for %p specifier
//     printf("Mem end at %p\n", mem_end);
//     printf("*************************************\n\n");
// }

chunk_ptr_t get_prev_free(chunk_ptr_t current_with_no_links) {
    chunk_ptr_t current_check = get_prev(current_with_no_links);

    while (current_check != NULL) {
        if (is_free(current_check)) return current_check;
        current_check = get_prev(current_check);
    }

    return NULL;
}

chunk_ptr_t get_next_free(chunk_ptr_t current_with_no_links) {
    chunk_ptr_t current_check = get_next(current_with_no_links);

    while (current_check != NULL) {
        if (is_free(current_check)) return current_check;
        current_check = get_next(current_check);
    }

    return NULL;
}

void stitch_two_unsafe(chunk_ptr_t before, chunk_ptr_t after) {
    before->next_free = after;
    after->prev_free = before;
}

void stitch_three_free(chunk_ptr_t prev_free, chunk_ptr_t current_no_links, chunk_ptr_t next_free) {
    if (prev_free == NULL) {
        current_no_links->prev_free = NULL;
    } else {
        stitch_two_unsafe(prev_free, current_no_links);
    }

    if (next_free == NULL) {
        current_no_links->next_free = NULL;
    } else {
        stitch_two_unsafe(current_no_links, next_free);
    }
}

void update_tail_check(chunk_ptr_t current) {
    if (current == NULL) return;

    struct chunk* next_addr = add_absolute(current, HEADER_OVERHEAD + get_size(current));

    bool next_out_of_bounds = out_of_bounds(next_addr);
    bool end_out_of_bounds = out_of_bounds(subtract_absolute(next_addr, 1));
    bool condition = next_out_of_bounds && !end_out_of_bounds;

    if (condition) {
        int a = 1;
        tail = current;
    }
        
}

void initialize_empty_chunk_no_coalesce(size_t prev_size, size_t current_size, chunk_ptr_t current) {

    assert(current_size >= HEADER_OVERHEAD + FREE_CHUNK_UNDERHEAD);
    // zero out
    memset(current, 0, HEADER_OVERHEAD + FREE_CHUNK_UNDERHEAD);

    // setup the part involving the chunk before
    current->prev_size_and_occupied_bit = prev_size << 1;
    chunk_ptr_t prev_chunk = get_prev(current);

    if (prev_chunk != NULL)
        current->prev_size_and_occupied_bit = prev_chunk->current_size_and_occupied_bit;
    else
        current->prev_size_and_occupied_bit = 0;
    
    // setup the part involving the current chunk
    current->current_size_and_occupied_bit = current_size << 1;
    chunk_ptr_t next_chunk = get_next(current);

    if (next_chunk != NULL)
        next_chunk->prev_size_and_occupied_bit = current->current_size_and_occupied_bit;

    // setup the linked list part
    // scan the left and right for free chunks
    chunk_ptr_t prev_free = get_prev_free(current);
    chunk_ptr_t next_free = get_next_free(current);

    stitch_three_free(prev_free, current, next_free);
}

void* my_sbrk(intptr_t increment) {
    if (increment == 0) {
        void *sbrk_return = sbrk(0);
        // printf("sbrk requested with size 0, returning %p\n", sbrk_return);
        return sbrk_return;
    }
    void* previous_break = sbrk(increment);
    void* current_break = sbrk(0);
    if (previous_break == (void*) -1) {
        // Handle error, sbrk failed
        size_t sbrk_false = 0;
        assert(sbrk_false);
    }

    // printf("sbrk requested with size %zu, returning %p\n", increment, previous_break);
    return current_break;
}

void init_everything() {
    if (!init) {
        mem_begin = my_sbrk(0);
        void *sbrk_return = my_sbrk(INIT_SIZE);

        assert(abs_ptr_diff(sbrk_return, mem_begin) == INIT_SIZE);
        
        mem_end = subtract_absolute(sbrk_return, 1);

        memset(mem_begin, 0, abs_ptr_diff(mem_end, mem_begin) + 1);

        head = (chunk_ptr_t) mem_begin;
        tail = head;

        initialize_empty_chunk_no_coalesce(0, INIT_SIZE - HEADER_OVERHEAD, head);

        init = true;

        tail_sanity_check();
    }
}

int set_occupied(chunk_ptr_t current, bool occupied) {

    tail_sanity_check();

    assert(current != NULL);
    assert(ptr_cmp(current, mem_begin) != PTR_LESS_THAN);
    assert(ptr_cmp(current, mem_end) == PTR_LESS_THAN);
    
    if (occupied) {
        current->current_size_and_occupied_bit |= 1;
    } else {
        current->current_size_and_occupied_bit &= ~1;
    }

    chunk_ptr_t next_chunk = get_next(current);
    if (next_chunk != NULL) {
        next_chunk->prev_size_and_occupied_bit = current->current_size_and_occupied_bit;
    }

    return SUCCESS;
}

chunk_ptr_t occupy_left_unsafe(chunk_ptr_t current, size_t occupancy) {
    // occupy the left side of a chunk

    // printf("OCCUPYING LEFT\n");
    size_t old_size = get_size(current);
    size_t new_free_size = old_size - occupancy - HEADER_OVERHEAD;
    size_t new_occupied_size = occupancy;
    chunk_ptr_t prev_free_p = current->prev_free;
    chunk_ptr_t next_free_p = current->next_free;
    
    // set address of right new chunk
    chunk_ptr_t new_free_chunk = (chunk_ptr_t) add_absolute(current, HEADER_OVERHEAD + occupancy);
    new_free_chunk->current_size_and_occupied_bit = new_free_size << 1;
    new_free_chunk->prev_size_and_occupied_bit = (new_occupied_size << 1) | 1;

    // update the chunk after it
    chunk_ptr_t chunk_after_new_free = get_next(new_free_chunk);
    if (chunk_after_new_free != NULL) {
        chunk_after_new_free->prev_size_and_occupied_bit = new_free_chunk->current_size_and_occupied_bit;
    }

    // update the free list
    new_free_chunk->prev_free = prev_free_p;
    new_free_chunk->next_free = next_free_p;
    if (prev_free_p != NULL) prev_free_p->next_free = new_free_chunk;
    if (next_free_p != NULL) next_free_p->prev_free = new_free_chunk;

    // set the current size
    current->current_size_and_occupied_bit = new_free_chunk->prev_size_and_occupied_bit;

    update_tail_check(new_free_chunk);
    
    return current;
}

chunk_ptr_t occupy_right_unsafe(chunk_ptr_t current, size_t occupancy) {
    size_t old_size = get_size(current);
    size_t new_free_size = old_size - occupancy - HEADER_OVERHEAD;
    size_t new_occupied_size = occupancy;

    assert(new_occupied_size >= FREE_CHUNK_UNDERHEAD);

    chunk_ptr_t new_occupied_chunk = (chunk_ptr_t) add_absolute(current, HEADER_OVERHEAD + new_free_size);

    // update the current 
    current->current_size_and_occupied_bit = new_free_size << 1;

    // update the occupied chunk
    new_occupied_chunk->prev_size_and_occupied_bit = current->current_size_and_occupied_bit;
    new_occupied_chunk->current_size_and_occupied_bit = (new_occupied_size << 1) | 1;

    // update the chunk after
    chunk_ptr_t chunk_after_new_occupied = get_next(new_occupied_chunk);
    if (chunk_after_new_occupied != NULL)
        chunk_after_new_occupied->prev_size_and_occupied_bit = new_occupied_chunk->current_size_and_occupied_bit;

    update_tail_check(new_occupied_chunk);
    
    return new_occupied_chunk;
}

chunk_ptr_t occupy_big_chunk_unsafe(chunk_ptr_t current, size_t occupancy) {
    // depending on which chunk is bigger, occupy on the side of the smaller adjacent chunk:
    chunk_ptr_t prev_chunk = get_prev(current);
    chunk_ptr_t next_chunk = get_next(current);

    if (prev_chunk == NULL || next_chunk == NULL) 
        return occupy_left_unsafe(current, occupancy);
    if (get_size(prev_chunk) > get_size(next_chunk))
        return occupy_right_unsafe(current, occupancy);
    else return occupy_left_unsafe(current, occupancy);
}

chunk_ptr_t occupy_chunk(chunk_ptr_t current, size_t occupancy) {
    assert(current != NULL);
    assert(occupancy > 0);
    assert(is_free(current));
    tail_sanity_check();

    size_t cur_size = get_size(current);

    // if can split into free chunks, then do it.
    if (cur_size >= occupancy && occupancy + MIN_CHUNK_SIZE > cur_size) {

        // link previous and next free chunks
        chunk_ptr_t prev_free = current->prev_free;
        chunk_ptr_t next_free = current->next_free;

        if (prev_free != NULL) prev_free->next_free = next_free;
        if (next_free != NULL) next_free->prev_free = prev_free;
        
        // set occupation
        set_occupied(current, true);

        return current;
    } else if (occupancy + MIN_CHUNK_SIZE <= cur_size) {
        return occupy_big_chunk_unsafe(current, occupancy);
    } 
    assert(false);
}

// expand the back, returns ptr to the tail UNOCCUPIED chunk
chunk_ptr_t expand_heap(size_t size_needed) {
    // tail is unoccupied but has enough memory
    
    
    assert(tail != NULL);
    assert(get_next(tail) == NULL);
    tail_sanity_check();

    if (is_free(tail) && get_size(tail) >= size_needed) {
        return tail;
    }
    
    // the below all require allocation.

    size_t orig_size = abs_ptr_diff(mem_end, mem_begin) + 1;

    size_t expand_size = orig_size;

    while(expand_size < size_needed + HEADER_OVERHEAD) expand_size <<= 1;

    void* old_mem_end = mem_end;
    void *sbrk_return = my_sbrk(expand_size);
    mem_end = subtract_absolute(sbrk_return, 1);
    memset(add_absolute(old_mem_end, 1), 0, abs_ptr_diff(mem_end, old_mem_end));

    // tail is unoccupied then we merge the tail with the allocated region
    // otherwise initiate a chunk and connect it into the free list

    if (is_free(tail)) {
        tail->current_size_and_occupied_bit += expand_size << 1;
    } else {
        // go to one past the tail
        chunk_ptr_t one_past_last = add_absolute(tail, HEADER_OVERHEAD+get_size(tail));
        assert(ptr_cmp(add_absolute(old_mem_end, 1), one_past_last) == PTR_EQUAL);
        initialize_empty_chunk_no_coalesce(get_size(tail), expand_size - HEADER_OVERHEAD, one_past_last);
        tail = one_past_last;
        // update free list

        chunk_ptr_t prev_free_p = get_prev_free(tail);
        tail->prev_free = prev_free_p;
        if (prev_free_p != NULL) prev_free_p->next_free = tail;
    }

    // debug_current_layout();

    assert(get_next(tail) == NULL);
    assert(mem_end == subtract_absolute(add_absolute(tail, HEADER_OVERHEAD+get_size(tail)),1));

    return tail;
}

// chunk_ptr_t coalesce_two_unsafe(chunk_ptr_t left, chunk_ptr_t right) {
//     assert(left != NULL && right != NULL);
//     assert(is_free(left) && is_free(right));

//     size_t new_size = get_size(left) + get_size(right) + HEADER_OVERHEAD;

//     // set the size and prev size of left
//     left->current_size_and_occupied_bit = new_size << 1;

//     // set the size and prev size of one past right
//     chunk_ptr_t next = get_next(left);
//     if (next != NULL) next->prev_size_and_occupied_bit = left->current_size_and_occupied_bit;

//     // link the previous and next free
//     // left ---- | prev & next .... right ---- | prev & next ....
//     // as we can see, left's prev does not change, and left does not have to change prev
//     // left's next does have to change, and left's next has to change prev
    
    
// }

void free_chunk(void* location) {
    tail_sanity_check();
    chunk_ptr_t current = subtract_absolute(location, HEADER_OVERHEAD);
    assert(!out_of_bounds(current));
    // unset the occupation bits 
    set_occupied(current, false);

    chunk_ptr_t left = get_prev(current), right = current;
    // if left is free, then expand to left. Update the current size of left and prev size of right

    if (left != NULL && is_free(left)) {
        size_t left_size = get_size(left);
        size_t right_size = get_size(right);
        chunk_ptr_t one_past_right = get_next(right);
        left->current_size_and_occupied_bit = (left_size + HEADER_OVERHEAD + right_size) << 1;
        
        if (one_past_right != NULL) 
            one_past_right->prev_size_and_occupied_bit = left->current_size_and_occupied_bit;
        
        // notice that the free list doesn't have to change here
    } else 
        left = current;

    // if right is free, then merge to right. Update the current size of center and prev size of one after right

    assert(is_free(left));
    right = get_next(left);
    
    if (right != NULL && is_free(right)) {
        size_t left_size = get_size(left);
        size_t right_size = get_size(right);
        chunk_ptr_t one_past_right = get_next(right);
        left->current_size_and_occupied_bit = (left_size + HEADER_OVERHEAD + right_size) << 1;

        if (one_past_right != NULL)
            one_past_right->prev_size_and_occupied_bit = left->current_size_and_occupied_bit;
    }

    // re-link previous and right free lists 

    chunk_ptr_t prev_free = get_prev_free(left);
    chunk_ptr_t next_free = get_next_free(left);

    stitch_three_free(prev_free, left, next_free);
    // update tail

    if (get_next(left) != NULL) update_tail_check(get_next(left));
    else update_tail_check(left);
}

#define ALIGNMENT 16
size_t round_to_align(size_t orig_allocation) {

    if (orig_allocation < FREE_CHUNK_UNDERHEAD) orig_allocation = FREE_CHUNK_UNDERHEAD;
    orig_allocation += HEADER_OVERHEAD;
    orig_allocation = (orig_allocation + (ALIGNMENT - 1)) & ~(ALIGNMENT - 1);
    orig_allocation -= HEADER_OVERHEAD;

    return orig_allocation;
}

void *ff_malloc(size_t allocation) {
    init_everything();
    tail_sanity_check();

    allocation = round_to_align(allocation);

    struct chunk* fitted_chunk = NULL;
    // scan through list
    struct chunk* current = head;
    if (!is_free(head)) current = get_next_free(head);

    while (current != NULL) {
        assert(is_free(current));
        if (get_size(current) >= allocation) {
            fitted_chunk = current;
            break;
        }
        current = current->next_free;
    }

    if (fitted_chunk == NULL) {
        fitted_chunk = expand_heap(allocation);
    }

    chunk_ptr_t chunk_location = occupy_chunk(fitted_chunk, allocation);

    tail_sanity_check();

    return add_absolute(chunk_location, HEADER_OVERHEAD);
};

void ff_free(void *location) {
    tail_sanity_check();
    free_chunk(location);
    tail_sanity_check();
}

void *bf_malloc(size_t allocation) {
    init_everything();
    tail_sanity_check();

    allocation = round_to_align(allocation);

    size_t best_fit = 0;
    chunk_ptr_t best_fit_chunk = NULL;
    chunk_ptr_t current = head;
    if (!is_free(head)) current = get_next_free(head);

    while (current != NULL) {
        assert(is_free(current));
        size_t cur_size = get_size(current);
        if (cur_size >= allocation) {
            if (best_fit_chunk == NULL) {
                best_fit_chunk = current;
                best_fit = cur_size;
            } else {
                if (cur_size < best_fit) {
                    best_fit_chunk = current;
                    best_fit = cur_size;
                }
            }
        }
        current = current->next_free;
    }

    if (best_fit_chunk == NULL) {
        best_fit_chunk = expand_heap(allocation);
    }

    chunk_ptr_t chunk_location = occupy_chunk(best_fit_chunk, allocation);

    tail_sanity_check();

    return add_absolute(chunk_location, HEADER_OVERHEAD);
};

void bf_free(void *location) {
    tail_sanity_check();
    free_chunk(location);
    tail_sanity_check();
};

