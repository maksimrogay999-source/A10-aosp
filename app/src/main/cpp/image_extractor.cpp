#include "image_extractor.h"
#include "ext4_extract.h"
#include <android/log.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <cstdint>
#include <cstring>
#include <vector>
#include <string>
#include <cstdio>
#include <algorithm>

#define TAG "A10_Extract"

// Android sparse image format
#define SPARSE_HEADER_MAGIC 0xed26ff3a
#define CHUNK_TYPE_RAW 0xCAC1
#define CHUNK_TYPE_FILL 0xCAC2
#define CHUNK_TYPE_DONT_CARE 0xCAC3
#define CHUNK_TYPE_CRC32 0xCAC4

#pragma pack(push, 1)
typedef struct sparse_header {
    uint32_t magic;
    uint16_t major_version;
    uint16_t minor_version;
    uint16_t file_hdr_sz;
    uint16_t chunk_hdr_sz;
    uint32_t blk_sz;
    uint32_t total_blks;
    uint32_t total_chunks;
    uint32_t image_checksum;
} sparse_header_t;

typedef struct chunk_header {
    uint16_t chunk_type;
    uint16_t reserved1;
    uint32_t chunk_sz;
    uint32_t total_sz;
} chunk_header_t;
#pragma pack(pop)

bool sparse_to_raw(const std::string& sparsePath, const std::string& rawPath, std::string& err) {
    int inFd = open(sparsePath.c_str(), O_RDONLY);
    if (inFd < 0) { err = "Cannot open sparse image"; return false; }
    int outFd = open(rawPath.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (outFd < 0) { close(inFd); err = "Cannot create raw image"; return false; }

    sparse_header_t hdr;
    if (read(inFd, &hdr, sizeof(hdr)) != sizeof(hdr) || hdr.magic != SPARSE_HEADER_MAGIC) {
        close(inFd); close(outFd);
        err = "Not a sparse image (or bad header)";
        return false;
    }

    __android_log_print(ANDROID_LOG_INFO, TAG, "Sparse: blk_sz=%u total_blks=%u chunks=%u",
                        hdr.blk_sz, hdr.total_blks, hdr.total_chunks);

    std::vector<uint8_t> buf;
    for (uint32_t i = 0; i < hdr.total_chunks; i++) {
        chunk_header_t ch;
        if (read(inFd, &ch, sizeof(ch)) != sizeof(ch)) { err = "Read chunk header failed"; goto fail; }
        uint64_t dataBytes = (uint64_t)ch.chunk_sz * hdr.blk_sz;
        if (ch.chunk_type == CHUNK_TYPE_RAW) {
            uint64_t toRead = ch.total_sz - sizeof(ch);
            buf.resize(1024 * 1024);
            uint64_t remaining = toRead;
            while (remaining > 0) {
                size_t n = (size_t)std::min<uint64_t>(remaining, buf.size());
                ssize_t r = read(inFd, buf.data(), n);
                if (r <= 0) { err = "Read raw chunk failed"; goto fail; }
                if (write(outFd, buf.data(), r) != r) { err = "Write raw chunk failed"; goto fail; }
                remaining -= r;
            }
        } else if (ch.chunk_type == CHUNK_TYPE_FILL) {
            uint32_t fillVal = 0;
            if (read(inFd, &fillVal, sizeof(fillVal)) != sizeof(fillVal)) { err = "Read fill failed"; goto fail; }
            std::vector<uint8_t> block(hdr.blk_sz);
            for (uint32_t b = 0; b < hdr.blk_sz; b += 4) memcpy(block.data() + b, &fillVal, 4);
            for (uint32_t c = 0; c < ch.chunk_sz; c++) {
                if (write(outFd, block.data(), block.size()) != (ssize_t)block.size()) { err = "Write fill failed"; goto fail; }
            }
        } else if (ch.chunk_type == CHUNK_TYPE_DONT_CARE) {
            // seek forward in output
            off_t off = lseek(outFd, dataBytes, SEEK_CUR);
            if (off == (off_t)-1) { err = "Seek failed"; goto fail; }
            // skip any extra data in chunk
            if (ch.total_sz > sizeof(ch)) lseek(inFd, ch.total_sz - sizeof(ch), SEEK_CUR);
        } else if (ch.chunk_type == CHUNK_TYPE_CRC32) {
            if (ch.total_sz > sizeof(ch)) lseek(inFd, ch.total_sz - sizeof(ch), SEEK_CUR);
        } else {
            // unknown, skip
            if (ch.total_sz > sizeof(ch)) lseek(inFd, ch.total_sz - sizeof(ch), SEEK_CUR);
            // but we must still account for space? best effort seek output
            lseek(outFd, dataBytes, SEEK_CUR);
        }
    }

    close(inFd); close(outFd);
    __android_log_print(ANDROID_LOG_INFO, TAG, "Sparse -> raw done: %s", rawPath.c_str());
    return true;
fail:
    close(inFd); close(outFd);
    return false;
}

bool image_extract_system(const std::string& systemImgPath, const std::string& outDir, std::string& err) {
    // Step 1: unsparse if needed
    std::string rawPath = systemImgPath + ".raw";
    // quick magic check
    int fd = open(systemImgPath.c_str(), O_RDONLY);
    if (fd < 0) { err = "Cannot open system.img"; return false; }
    uint32_t magic = 0;
    read(fd, &magic, sizeof(magic));
    close(fd);

    std::string src = systemImgPath;
    if (magic == SPARSE_HEADER_MAGIC) {
        if (!sparse_to_raw(systemImgPath, rawPath, err)) return false;
        src = rawPath;
    } else {
        __android_log_print(ANDROID_LOG_INFO, TAG, "system.img not sparse, using as-is");
    }

    // Step 2: ext4 extraction
    __android_log_print(ANDROID_LOG_INFO, TAG, "Extracting ext4 from %s to %s", src.c_str(), outDir.c_str());
    std::string extErr;
    if (!ext4_extract_image(src, outDir, extErr)) {
        err = "ext4 extract failed: " + extErr;
        __android_log_print(ANDROID_LOG_ERROR, TAG, "%s", err.c_str());
        return false;
    }
    __android_log_print(ANDROID_LOG_INFO, TAG, "ext4 extraction done");
    return true;
}