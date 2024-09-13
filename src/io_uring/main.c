/* Vectored I/O with io_uring */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/uio.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/mman.h>

#include <linux/io_uring.h>

#define NUM_ENTRIES 4
#define BLKSZ 4096

static char array[BLKSZ];
static struct iovec iov[NUM_ENTRIES];
static char read_path[] = "/tmp/dump.txt";
void *sq_ptr, *cq_ptr;
size_t s_ring_sz, c_ring_sz;

static inline void barrier(void)
{
    asm("mfence" ::: "memory");
}

struct sq_ring
{
    uint32_t *head;
    uint32_t *tail;
    uint32_t *ring_mask;
    uint32_t *ring_entries;
    uint32_t *flags;
    uint32_t *dropped;
    uint32_t *array;
    struct io_uring_sqe *sqes;
};

struct cq_ring
{
    uint32_t *head;
    uint32_t *tail;
    uint32_t *ring_mask;
    uint32_t *ring_entries;
    struct io_uring_cqe *cqes;
};

static inline int io_uring_setup(uint32_t entries, struct io_uring_params *p)
{
    return (int)syscall(__NR_io_uring_setup, entries, p);
}

static inline int io_uring_enter(int ring_fd, uint32_t to_submit,
                                 uint32_t min_complete, uint32_t flags)
{
    return (int)syscall(__NR_io_uring_enter, ring_fd, to_submit, min_complete, flags, NULL, 0);
}

static struct io_uring_sqe *init_sqe(struct sq_ring *s_ring, uint64_t off, int fd, uint8_t op)
{
    struct io_uring_sqe *sqe;
    uint32_t tail, index;

    tail = *s_ring->tail;
    index = tail & (*s_ring->ring_mask);
    sqe = &s_ring->sqes[index];

    sqe->opcode = op;
    sqe->fd = fd;
    sqe->off = off;
    sqe->addr = (uint64_t)iov;
    sqe->len = NUM_ENTRIES;
    // sqe->user_data = user_data;

    s_ring->array[index] = index;
    tail++; // Advance

    barrier();
    *s_ring->tail = tail;
    barrier();

    return sqe;
}

static int consume_cqe(struct cq_ring *c_ring)
{
    struct io_uring_cqe *cqe;
    uint32_t head, index;

    head = *c_ring->head;
    barrier();
    if (head != *c_ring->tail)
    {
        index = head & (*c_ring->ring_mask);
        cqe = &c_ring->cqes[index];

        head++; // advance
    }
    else if (head == *c_ring->tail)
    {
        /* The completion queue is now empty */
        return -2;
    }

    *c_ring->head = head;
    barrier();
    return cqe->res;
}

struct sq_ring *init_sq_ring(int ring_fd, struct io_uring_params *p)
{
    struct sq_ring *s_ring;
    // void *sq_ptr;
    size_t s_ring_sz;

    s_ring_sz = p->sq_off.array + p->sq_entries * sizeof(uint32_t);

    s_ring = malloc(sizeof(struct sq_ring));
    if (!s_ring)
    {
        perror("init_sq_ring: malloc");
        return NULL;
    }

    sq_ptr = mmap(NULL, s_ring_sz,
                  PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, ring_fd,
                  IORING_OFF_SQ_RING);

    if (sq_ptr == MAP_FAILED)
    {
        perror("init_sq_ring: mmap");
        return NULL;
    }

    s_ring->head = sq_ptr + p->sq_off.head;
    s_ring->tail = sq_ptr + p->sq_off.tail;
    s_ring->ring_mask = sq_ptr + p->sq_off.ring_mask;
    s_ring->ring_entries = sq_ptr + p->sq_off.ring_entries;
    s_ring->flags = sq_ptr + p->sq_off.flags;
    s_ring->dropped = sq_ptr + p->sq_off.dropped;
    s_ring->array = sq_ptr + p->sq_off.array;

    s_ring->sqes = mmap(NULL, p->sq_entries * sizeof(struct io_uring_sqe),
                        PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, ring_fd,
                        IORING_OFF_SQES);
    if (s_ring->sqes == MAP_FAILED)
    {
        perror("init_sq_ring: mmap");
        return NULL;
    }
    return s_ring;
}

struct cq_ring *init_cq_ring(int ring_fd, struct io_uring_params *p)
{
    struct cq_ring *c_ring;
    // void *cq_ptr;
    // size_t c_ring_sz;

    c_ring_sz = p->cq_off.cqes + p->cq_entries * sizeof(struct io_uring_cqe);
    c_ring = malloc(sizeof(struct cq_ring));
    if (!c_ring)
    {
        perror("init_cq_ring: malloc");
        return NULL;
    }

    cq_ptr = mmap(NULL, c_ring_sz,
                  PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, ring_fd,
                  IORING_OFF_CQ_RING);
    if (cq_ptr == MAP_FAILED)
    {
        perror("init_cq_ring: mmap");
        return NULL;
    }

    c_ring->head = cq_ptr + p->cq_off.head;
    c_ring->tail = cq_ptr + p->cq_off.tail;
    c_ring->ring_mask = cq_ptr + p->cq_off.ring_mask;
    c_ring->ring_entries = cq_ptr + p->cq_off.ring_entries;
    c_ring->cqes = cq_ptr + p->cq_off.cqes;
    return c_ring;
}

static void cleanup_allocs(struct sq_ring *s_ring, struct cq_ring *c_ring, struct io_uring_params *params) {
    munmap(s_ring->sqes, params->sq_entries * sizeof(struct io_uring_sqe));
    munmap(sq_ptr, s_ring_sz);
    munmap(cq_ptr, c_ring_sz);
    free(s_ring);
    free(c_ring);
}

int main(int argc, char *argv[])
{
    struct io_uring_params params;
    struct sq_ring *s_ring;
    struct cq_ring *c_ring;
    uint64_t offset;
    int fd, ret, consumed;
    char *total_chunk;

    memset(&params, 0, sizeof(params));
    int ring_fd = io_uring_setup(NUM_ENTRIES, &params);
    if (ring_fd == -1)
    {
        perror("io_uring_setup");
        exit(EXIT_FAILURE);
    }

    s_ring = init_sq_ring(ring_fd, &params);
    if (!s_ring)
    {
        fprintf(stderr, "init_sq_ring error\n");
        exit(EXIT_FAILURE);
    }

    c_ring = init_cq_ring(ring_fd, &params);
    if (!c_ring)
    {
        fprintf(stderr, "init_cq_ring error\n");
        exit(EXIT_FAILURE);
    }

    fd = open(read_path, O_RDONLY);
    if (fd == -1)
    {
        perror("open");
        exit(EXIT_FAILURE);
    }

    offset = 0;

    /* Get vectored buffers in single allocation */
    total_chunk = malloc(BLKSZ * NUM_ENTRIES);
    if (!total_chunk)
    {
        close(fd);
        perror("malloc");
        exit(EXIT_FAILURE);
    }
    memset(total_chunk, 0, BLKSZ * NUM_ENTRIES);

    while (1)
    {

        /* Fill up the io vector */
        for (size_t i = 0; i < NUM_ENTRIES; i++)
        {
            iov[i].iov_base = total_chunk + (BLKSZ * i);
            iov[i].iov_len = BLKSZ;
        }

        init_sqe(s_ring, offset, fd, IORING_OP_READV);

        ret = io_uring_enter(ring_fd, NUM_ENTRIES, 1, IORING_ENTER_GETEVENTS);
        if (ret < 0)
        {
            perror("io_uring_enter");
            goto exit_error;
        }

        consumed = consume_cqe(c_ring);
        for (size_t k = 0; k < NUM_ENTRIES; k++)
        {
            printf("%s", (char *)iov[k].iov_base);

            /* Attempt to reset chunk 8 bytes at a time */
            memset((uint64_t*)total_chunk, 0, BLKSZ * NUM_ENTRIES);
        }

        if (consumed == -1) // Error
        {

            perror("consume_cqe");
            goto exit_error;
        }
        else if (consumed < -2) // Error
        {

            fprintf(stderr, "Error: %s\n", strerror(abs(consumed)));
            goto exit_error;
        }
        else if (consumed == -2) // End of file
        {
            break;
        }
        else if (consumed == 0) // Empty
        {
            break;
        }

        offset += (BLKSZ * NUM_ENTRIES);
    }
    printf("\n");

    close(fd);
    free(total_chunk);
    cleanup_allocs(s_ring, c_ring, &params);
    return EXIT_SUCCESS;

exit_error:
    close(fd);
    free(total_chunk);
    cleanup_allocs(s_ring, c_ring, &params);
    exit(EXIT_FAILURE);
}
