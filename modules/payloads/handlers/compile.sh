#!/bin/bash
# compile_multi_handler.sh
echo "Compiling Multi Handler..."

gcc -o /root/lazy-framework/modules/payloads/handlers/multi_handler /root/lazy-framework/modules/payloads/handlers/multi_handler.c \
    -pthread -static -O2

if [ $? -eq 0 ]; then
    echo "Compilation successful!"
    chmod +x /root/lazy-framework/modules/payloads/handlers/multi_handler
else
    echo "Compilation failed!"
    exit 1
fi
