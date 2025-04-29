#!/bin/bash

# Set up cross-compilation environment
export CC=x86_64-w64-mingw32-gcc
export CXX=x86_64-w64-mingw32-g++
export WINDRES=x86_64-w64-mingw32-windres
export AR=x86_64-w64-mingw32-ar
export RANLIB=x86_64-w64-mingw32-ranlib

# Create build directory
mkdir -p build
cd build

# Compile the fuzzer
$CXX -std=c++17 \
    -static-libgcc -static-libstdc++ \
    -o IotSenderFuzzer.exe \
    ../IotSenderFuzzer.cpp \
    -lcrypt32

# Check if compilation was successful
if [ $? -eq 0 ]; then
    echo "Compilation successful!"
    echo "Binary created: build/IotSenderFuzzer.exe"
    
    # Create a zip file with the binary
    echo "Creating distribution package..."
    mkdir -p ../dist
    cp IotSenderFuzzer.exe ../dist/
    cd ../dist
    zip -r IotSenderFuzzer_Windows.zip IotSenderFuzzer.exe
    echo "Distribution package created: dist/IotSenderFuzzer_Windows.zip"
else
    echo "Compilation failed!"
    exit 1
fi 
