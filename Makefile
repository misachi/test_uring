CC := gcc
OUT_DIR := /tmp/drive_io
PERF_DIR := perf_out
CURR_DIR := $(shell pwd)
FLAME_OUT_FILE := profile1
EXECUTABLE := iouring_raw_main
OUT_FILE := $(OUT_DIR)/$(EXECUTABLE)

create_dir:
	@mkdir -p $(OUT_DIR) $(PERF_DIR)

rw: create_dir
	@gcc -g src/readwrite/main.c -o $(OUT_DIR)/rw_main.o
	@$(OUT_DIR)/rw_main.o

io_uring: create_dir
	@gcc -g src/io_uring/raw/main.c -o $(OUT_DIR)/iouring_raw_main.o
	@$(OUT_DIR)/iouring_raw_main.o

io_uring_iovec: create_dir
	@gcc -g src/io_uring/raw/iov_main.c -o $(OUT_DIR)/iouring_raw_iov_main.o
	@$(OUT_DIR)/iouring_raw_iov_main.o

io_uring_iovec_mt: create_dir
	@gcc -g src/io_uring/raw/mt_main.c -o $(OUT_DIR)/iouring_raw_iov_main_mt.o
	@$(OUT_DIR)/iouring_raw_iov_main_mt.o

perf:
	@cd $(OUT_DIR); \
	sudo perf record -F 99 -g $(OUT_FILE); \
	sudo perf script | stackcollapse-perf.pl > out; \
	flamegraph.pl --colors=blue out > $(CURR_DIR)/$(PERF_DIR)/$(FLAME_OUT_FILE).svg; \
	cd $(CURR_DIR);

clean:
	@rm -f out *.data *.data.old *.o $(OUT_DIR)/*.o $(OUT_DIR)/*.data $(OUT_DIR)/*.data.old