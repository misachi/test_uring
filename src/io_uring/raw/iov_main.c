/* Vectored I/O with io_uring - Single threaded; one thread sends sqes and receives cqes */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include <linux/io_uring.h>

#define IOV_NUM_ENTRIES 64
#define QUEUE_DEPTH 240
#define BLKSZ 4096

static char array[BLKSZ];
static char read_path[] = "/tmp/bigfile.txt";
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

static struct io_uring_sqe *init_sqe(struct sq_ring *s_ring, uint64_t off, int fd, uint8_t op, struct iovec *iov)
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
    sqe->len = IOV_NUM_ENTRIES;
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

static void cleanup_allocs(struct sq_ring *s_ring, struct cq_ring *c_ring, struct io_uring_params *params)
{
    munmap(s_ring->sqes, params->sq_entries * sizeof(struct io_uring_sqe));
    munmap(sq_ptr, s_ring_sz);
    munmap(cq_ptr, c_ring_sz);
    free(s_ring);
    free(c_ring);
}

int main(int argc, char *argv[])
{
    clock_t start, end;
    double cpu_time_used;
    struct io_uring_params params;
    struct sq_ring *s_ring;
    struct cq_ring *c_ring;
    uint64_t offset;
    int fd, ret, consumed, chunk_size;
    char *total_chunk;
    struct iovec iovecs[QUEUE_DEPTH][IOV_NUM_ENTRIES];
    char *ptr;
    char buf[BLKSZ];
    struct stat finfo;

    start = clock();
    memset(&params, 0, sizeof(params));
    int ring_fd = io_uring_setup(QUEUE_DEPTH, &params);
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

    if (fstat(fd, &finfo) == -1)
    {
        perror("fstat");
        close(fd);
        exit(EXIT_FAILURE);
    }

    /* Get vectored buffers in single allocation */
    chunk_size = BLKSZ * IOV_NUM_ENTRIES * QUEUE_DEPTH;
    total_chunk = malloc(chunk_size);
    if (!total_chunk)
    {
        close(fd);
        perror("malloc");
        exit(EXIT_FAILURE);
    }
    memset((uint64_t *)total_chunk, 0, chunk_size);
    ptr = total_chunk;

    /* Fill up the io vector */
    for (size_t i = 0; i < QUEUE_DEPTH; i++)
    {
        for (size_t k = 0; k < IOV_NUM_ENTRIES; k++)
        {
            iovecs[i][k].iov_base = ptr;
            iovecs[i][k].iov_len = BLKSZ;
            ptr = iovecs[i][k].iov_base + BLKSZ;
        }
    }

    offset = 0;

    while (1)
    {
        for (size_t j = 0; j < QUEUE_DEPTH; j++)
        {
            init_sqe(s_ring, offset, fd, IORING_OP_READV, iovecs[j]);
            offset += (BLKSZ * IOV_NUM_ENTRIES);
        }

        ret = io_uring_enter(ring_fd, QUEUE_DEPTH, 1, IORING_ENTER_GETEVENTS);
        if (ret < 0)
        {
            perror("io_uring_enter");
            goto exit_error;
        }

        // printf("%s", total_chunk);

        /*
         * Consume each of the CQEs as required
         */
        for (size_t t = 0; consumed >= 0 && t < QUEUE_DEPTH; consumed = consume_cqe(c_ring))
        {
            if (consumed == 0)
                continue;

            /*
             * Do something with the the read blocks
             */
            // for (size_t k = 0; k < IOV_NUM_ENTRIES; k++)
            // {
            //     memcpy(buf, iovecs[t][k].iov_base, BLKSZ);
            //     printf("%s", buf);
            // }
            t++;
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
        else if ((consumed == -2 || consumed == 0) && offset >= finfo.st_size) // End of file or empty
        {
            printf("\nEmpty or EOF\n");
            goto success;
        }
        // memset((uint64_t *)total_chunk, 0, chunk_size);
    }

success:
    printf("\n");
    end = clock();
    cpu_time_used = ((double)(end - start)) / CLOCKS_PER_SEC;
    printf("Time: %f seconds\n", cpu_time_used);

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
