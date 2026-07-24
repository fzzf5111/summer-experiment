SEAL_PREFIX ?= ../.local
BUILD_DIR ?= build

.PHONY: all run clean

all:
	cmake -S . -B $(BUILD_DIR) -DCMAKE_PREFIX_PATH=$(abspath $(SEAL_PREFIX))
	cmake --build $(BUILD_DIR)

run: all
	./$(BUILD_DIR)/seal_bfv_conv2d

clean:
	rm -rf $(BUILD_DIR)
