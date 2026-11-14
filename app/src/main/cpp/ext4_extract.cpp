#include "ext4_extract.h"
#include <android/log.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <errno.h>
#include <cstring>
#include <string>
#include <vector>
#include <algorithm>
#include <cstdio>

#define TAG "A10_Ext4"

#define EXT4_SUPER_MAGIC 0xEF53
#define EXT4_NDIR_BLOCKS 12
#define EXT4_EXTENTS_FL 0x00080000
#define EXT4_INLINE_DATA_FL 0x10000000
#define EXT4_FT_UNKNOWN 0
#define EXT4_FT_REG_FILE 1
#define EXT4_FT_DIR 2
#define EXT4_FT_CHRDEV 3
#define EXT4_FT_BLKDEV 4
#define EXT4_FT_FIFO 5
#define EXT4_FT_SOCK 6
#define EXT4_FT_SYMLINK 7

#pragma pack(push, 1)
struct ext4_super_block {
    uint32_t s_inodes_count;
    uint32_t s_blocks_count_lo;
    uint32_t s_r_blocks_count_lo;
    uint32_t s_free_blocks_count_lo;
    uint32_t s_free_inodes_count;
    uint32_t s_first_data_block;
    uint32_t s_log_block_size;
    uint32_t s_log_cluster_size;
    uint32_t s_blocks_per_group;
    uint32_t s_clusters_per_group;
    uint32_t s_inodes_per_group;
    uint32_t s_mtime;
    uint32_t s_wtime;
    uint16_t s_mnt_count;
    uint16_t s_max_mnt_count;
    uint16_t s_magic;
    uint16_t s_state;
    uint16_t s_errors;
    uint16_t s_minor_rev_level;
    uint32_t s_lastcheck;
    uint32_t s_checkinterval;
    uint32_t s_creator_os;
    uint32_t s_rev_level;
    uint16_t s_def_resuid;
    uint16_t s_def_resgid;
    uint32_t s_first_ino;
    uint16_t s_inode_size;
    uint16_t s_block_group_nr;
    uint32_t s_feature_compat;
    uint32_t s_feature_incompat;
    uint32_t s_feature_ro_compat;
    uint8_t  s_uuid[16];
    char     s_volume_name[16];
    char     s_last_mounted[64];
    uint32_t s_algorithm_usage_bitmap;
    uint8_t  s_prealloc_blocks;
    uint8_t  s_prealloc_dir_blocks;
    uint16_t s_reserved_gdt_blocks;
    uint8_t  s_journal_uuid[16];
    uint32_t s_journal_inum;
    uint32_t s_journal_dev;
    uint32_t s_last_orphan;
    uint32_t s_hash_seed[4];
    uint8_t  s_def_hash_version;
    uint8_t  s_jnl_backup_type;
    uint16_t s_desc_size;
    uint32_t s_default_mount_opts;
    uint32_t s_first_meta_bg;
    uint32_t s_mkfs_time;
    uint32_t s_jnl_blocks[17];
    uint32_t s_blocks_count_hi;
    uint32_t s_r_blocks_count_hi;
    uint32_t s_free_blocks_count_hi;
    uint16_t s_min_extra_isize;
    uint16_t s_want_extra_isize;
    uint32_t s_flags;
    uint16_t s_raid_stride;
    uint16_t s_mmp_update_interval;
    uint64_t s_mmp_block;
    uint32_t s_raid_stripe_width;
    uint8_t  s_log_groups_per_flex;
    uint8_t  s_checksum_type;
    uint8_t  s_encryption_level;
    uint8_t  s_reserved_pad;
    uint64_t s_kbytes_written;
    uint32_t s_snapshot_inum;
    uint32_t s_snapshot_id;
    uint64_t s_snapshot_r_blocks_count;
    uint32_t s_snapshot_list;
    uint32_t s_error_count;
    uint32_t s_first_error_time;
    uint32_t s_first_error_ino;
    uint64_t s_first_error_block;
    uint8_t  s_first_error_func[32];
    uint32_t s_first_error_line;
    uint32_t s_last_error_time;
    uint32_t s_last_error_ino;
    uint32_t s_last_error_line;
    uint64_t s_last_error_block;
    uint8_t  s_last_error_func[32];
    char     s_mount_opts[64];
    uint32_t s_usr_quota_inum;
    uint32_t s_grp_quota_inum;
    uint32_t s_overhead_clusters;
    uint32_t s_backup_bgs[2];
    uint8_t  s_encrypt_algos[4];
    uint8_t  s_encrypt_pw_salt[16];
    uint32_t s_lpf_ino;
    uint32_t s_prj_quota_inum;
    uint32_t s_checksum_seed;
    uint32_t s_reserved[98];
    uint32_t s_checksum;
};

struct ext4_group_desc {
    uint32_t bg_block_bitmap_lo;
    uint32_t bg_inode_bitmap_lo;
    uint32_t bg_inode_table_lo;
    uint16_t bg_free_blocks_count_lo;
    uint16_t bg_free_inodes_count_lo;
    uint16_t bg_used_dirs_count_lo;
    uint16_t bg_flags;
    uint32_t bg_exclude_bitmap_lo;
    uint16_t bg_block_bitmap_csum_lo;
    uint16_t bg_inode_bitmap_csum_lo;
    uint16_t bg_itable_unused_lo;
    uint16_t bg_checksum;
    // 64-bit fields may follow if desc_size > 32
    uint32_t bg_block_bitmap_hi;
    uint32_t bg_inode_bitmap_hi;
    uint32_t bg_inode_table_hi;
    uint16_t bg_free_blocks_count_hi;
    uint16_t bg_free_inodes_count_hi;
    uint16_t bg_used_dirs_count_hi;
    uint16_t bg_itable_unused_hi;
    uint32_t bg_exclude_bitmap_hi;
    uint16_t bg_block_bitmap_csum_hi;
    uint16_t bg_inode_bitmap_csum_hi;
    uint32_t bg_reserved;
};

struct ext4_inode {
    uint16_t i_mode;
    uint16_t i_uid;
    uint32_t i_size_lo;
    uint32_t i_atime;
    uint32_t i_ctime;
    uint32_t i_mtime;
    uint32_t i_dtime;
    uint16_t i_gid;
    uint16_t i_links_count;
    uint32_t i_blocks_lo;
    uint32_t i_flags;
    uint32_t i_osd1;
    uint32_t i_block[15];
    uint32_t i_generation;
    uint32_t i_file_acl_lo;
    uint32_t i_size_high;
    uint32_t i_obso_faddr;
    uint8_t  i_osd2[12];
    uint16_t i_extra_isize;
    uint16_t i_checksum_hi;
    uint32_t i_ctime_extra;
    uint32_t i_mtime_extra;
    uint32_t i_atime_extra;
    uint32_t i_crtime;
    uint32_t i_crtime_extra;
    uint32_t i_version_hi;
    uint32_t i_projid;
};

struct ext4_dir_entry_2 {
    uint32_t inode;
    uint16_t rec_len;
    uint8_t  name_len;
    uint8_t  file_type;
    char     name[];
};

struct ext4_extent_header {
    uint16_t eh_magic;
    uint16_t eh_entries;
    uint16_t eh_max;
    uint16_t eh_depth;
    uint32_t eh_generation;
};

struct ext4_extent {
    uint32_t ee_block;
    uint16_t ee_len;
    uint16_t ee_start_hi;
    uint32_t ee_start_lo;
};

struct ext4_extent_idx {
    uint32_t ei_block;
    uint32_t ei_leaf_lo;
    uint16_t ei_leaf_hi;
    uint16_t ei_unused;
};
#pragma pack(pop)

static bool read_at(int fd, uint64_t off, void* buf, size_t len) {
    ssize_t r = pread(fd, buf, len, (off_t)off);
    return r == (ssize_t)len;
}

static bool ensure_dir(const std::string& path) {
    if (path.empty()) return true;
    size_t pos = 0;
    while (true) {
        pos = path.find('/', pos + 1);
        std::string sub = (pos == std::string::npos) ? path : path.substr(0, pos);
        if (!sub.empty()) {
            if (mkdir(sub.c_str(), 0755) != 0 && errno != EEXIST) return false;
        }
        if (pos == std::string::npos) break;
    }
    return true;
}

struct Ext4 {
    int fd = -1;
    ext4_super_block sb{};
    uint32_t block_size = 0;
    uint32_t inode_size = 0;
    uint32_t desc_size = 32;
    uint64_t groups = 0;
    uint64_t blocks_count = 0;

    bool open(const std::string& path) {
        fd = ::open(path.c_str(), O_RDONLY);
        if (fd < 0) return false;
        if (!read_at(fd, 1024, &sb, sizeof(sb))) return false;
        if (sb.s_magic != EXT4_SUPER_MAGIC) return false;
        block_size = 1024u << sb.s_log_block_size;
        inode_size = sb.s_rev_level >= 1 ? sb.s_inode_size : 128;
        desc_size = (sb.s_feature_incompat & 0x80 /*INCOMPAT_64BIT*/) && sb.s_desc_size ? sb.s_desc_size : 32;
        blocks_count = sb.s_blocks_count_lo | ((uint64_t)sb.s_blocks_count_hi << 32);
        groups = (blocks_count + sb.s_blocks_per_group - 1) / sb.s_blocks_per_group;
        __android_log_print(ANDROID_LOG_INFO, TAG, "ext4: bs=%u is=%u groups=%llu desc=%u",
                            block_size, inode_size, (unsigned long long)groups, desc_size);
        return true;
    }
    void close() { if (fd >= 0) { ::close(fd); fd = -1; } }

    bool read_block(uint64_t block, void* buf) {
        return read_at(fd, block * block_size, buf, block_size);
    }

    bool read_inode(uint32_t ino, ext4_inode& out) {
        if (ino == 0) return false;
        uint32_t group = (ino - 1) / sb.s_inodes_per_group;
        uint32_t index = (ino - 1) % sb.s_inodes_per_group;
        uint64_t gdt_block = (block_size == 1024) ? 2 : 1;
        uint64_t desc_off = gdt_block * block_size + (uint64_t)group * desc_size;
        ext4_group_desc gd{};
        if (!read_at(fd, desc_off, &gd, std::min<uint32_t>(desc_size, (uint32_t)sizeof(gd)))) return false;
        uint64_t inode_table = gd.bg_inode_table_lo;
        if (desc_size >= 64) inode_table |= ((uint64_t)gd.bg_inode_table_hi << 32);
        uint64_t inode_off = inode_table * block_size + (uint64_t)index * inode_size;
        memset(&out, 0, sizeof(out));
        return read_at(fd, inode_off, &out, std::min<uint32_t>(inode_size, (uint32_t)sizeof(out)));
    }

    bool read_extent_node(const void* nodeBuf, uint64_t logical_block, uint64_t& phys_block);
    bool extent_lookup(const ext4_inode& inode, uint64_t logical_block, uint64_t& phys_block);
    bool get_file_block(const ext4_inode& inode, uint64_t logical_block, uint64_t& phys_block);

    bool extract_inode(uint32_t ino, const std::string& outPath, int depth);
    bool extract_dir(const ext4_inode& inode, const std::string& outPath, int depth);
    bool extract_file(const ext4_inode& inode, const std::string& outPath);
    bool extract_symlink(const ext4_inode& inode, const std::string& outPath);
};

bool Ext4::read_extent_node(const void* nodeBuf, uint64_t logical_block, uint64_t& phys_block) {
    auto* eh = (const ext4_extent_header*)nodeBuf;
    if (eh->eh_magic != 0xF30A) return false;
    if (eh->eh_depth == 0) {
        auto* ex = (const ext4_extent*)((const uint8_t*)nodeBuf + sizeof(ext4_extent_header));
        for (uint16_t i = 0; i < eh->eh_entries; i++) {
            uint64_t start = ex[i].ee_block;
            uint32_t len = ex[i].ee_len;
            if (len > 32768) len -= 32768; // unwritten
            if (logical_block >= start && logical_block < start + len) {
                uint64_t pstart = ex[i].ee_start_lo | ((uint64_t)ex[i].ee_start_hi << 32);
                phys_block = pstart + (logical_block - start);
                return true;
            }
        }
        return false;
    } else {
        auto* idx = (const ext4_extent_idx*)((const uint8_t*)nodeBuf + sizeof(ext4_extent_header));
        int chosen = -1;
        for (uint16_t i = 0; i < eh->eh_entries; i++) {
            if (idx[i].ei_block <= logical_block) chosen = i;
            else break;
        }
        if (chosen < 0) return false;
        uint64_t leaf = idx[chosen].ei_leaf_lo | ((uint64_t)idx[chosen].ei_leaf_hi << 32);
        std::vector<uint8_t> blk(block_size);
        if (!read_block(leaf, blk.data())) return false;
        return read_extent_node(blk.data(), logical_block, phys_block);
    }
}

bool Ext4::extent_lookup(const ext4_inode& inode, uint64_t logical_block, uint64_t& phys_block) {
    return read_extent_node((const void*)inode.i_block, logical_block, phys_block);
}

bool Ext4::get_file_block(const ext4_inode& inode, uint64_t logical_block, uint64_t& phys_block) {
    if (inode.i_flags & EXT4_EXTENTS_FL) {
        return extent_lookup(inode, logical_block, phys_block);
    }
    // simple indirect blocks fallback
    if (logical_block < 12) {
        phys_block = inode.i_block[logical_block];
        return phys_block != 0;
    }
    uint64_t ptrs_per_block = block_size / 4;
    uint64_t idx = logical_block - 12;
    if (idx < ptrs_per_block) {
        std::vector<uint32_t> tbl(ptrs_per_block);
        if (!read_block(inode.i_block[12], tbl.data())) return false;
        phys_block = tbl[idx];
        return phys_block != 0;
    }
    idx -= ptrs_per_block;
    if (idx < ptrs_per_block * ptrs_per_block) {
        std::vector<uint32_t> tbl(ptrs_per_block);
        if (!read_block(inode.i_block[13], tbl.data())) return false;
        uint64_t l1 = idx / ptrs_per_block;
        uint64_t l2 = idx % ptrs_per_block;
        if (!tbl[l1]) return false;
        if (!read_block(tbl[l1], tbl.data())) return false;
        phys_block = tbl[l2];
        return phys_block != 0;
    }
    // double+ indirect omitted for simplicity
    return false;
}

bool Ext4::extract_file(const ext4_inode& inode, const std::string& outPath) {
    uint64_t size = inode.i_size_lo | ((uint64_t)inode.i_size_high << 32);
    // remove existing
    ::unlink(outPath.c_str());
    int ofd = ::open(outPath.c_str(), O_WRONLY | O_CREAT | O_TRUNC, inode.i_mode & 07777);
    if (ofd < 0) return false;
    if (size == 0) { ::close(ofd); return true; }
    // inline data
    if (inode.i_flags & EXT4_INLINE_DATA_FL) {
        // inline data stored in i_block area and xattrs; simplified: try first 60 bytes
        size_t n = std::min<uint64_t>(size, 60);
        write(ofd, inode.i_block, n);
        ::close(ofd);
        return true;
    }
    std::vector<uint8_t> buf(block_size);
    uint64_t remaining = size;
    uint64_t lb = 0;
    while (remaining > 0) {
        uint64_t pb = 0;
        if (!get_file_block(inode, lb, pb) || pb == 0) {
            // sparse hole
            memset(buf.data(), 0, buf.size());
            size_t n = (size_t)std::min<uint64_t>(remaining, block_size);
            if (lseek(ofd, n, SEEK_CUR) == (off_t)-1) { ::close(ofd); return false; }
            remaining -= n;
        } else {
            if (!read_block(pb, buf.data())) { ::close(ofd); return false; }
            size_t n = (size_t)std::min<uint64_t>(remaining, block_size);
            if (write(ofd, buf.data(), n) != (ssize_t)n) { ::close(ofd); return false; }
            remaining -= n;
        }
        lb++;
    }
    ::close(ofd);
    chmod(outPath.c_str(), inode.i_mode & 07777);
    return true;
}

bool Ext4::extract_symlink(const ext4_inode& inode, const std::string& outPath) {
    uint64_t size = inode.i_size_lo | ((uint64_t)inode.i_size_high << 32);
    std::string target;
    if (size <= 60 && !(inode.i_flags & EXT4_EXTENTS_FL)) {
        target.assign((const char*)inode.i_block, (size_t)size);
    } else {
        // read from data blocks
        std::vector<char> buf((size_t)size + 1, 0);
        std::vector<uint8_t> blk(block_size);
        uint64_t remaining = size, lb = 0, off = 0;
        while (remaining > 0) {
            uint64_t pb = 0;
            if (!get_file_block(inode, lb, pb) || pb == 0) break;
            if (!read_block(pb, blk.data())) break;
            size_t n = (size_t)std::min<uint64_t>(remaining, block_size);
            memcpy(buf.data() + off, blk.data(), n);
            off += n; remaining -= n; lb++;
        }
        target.assign(buf.data(), (size_t)size);
    }
    ::unlink(outPath.c_str());
    return symlink(target.c_str(), outPath.c_str()) == 0;
}

bool Ext4::extract_dir(const ext4_inode& inode, const std::string& outPath, int depth) {
    if (depth > 64) return true;
    ensure_dir(outPath);
    chmod(outPath.c_str(), inode.i_mode & 07777);
    uint64_t size = inode.i_size_lo | ((uint64_t)inode.i_size_high << 32);
    std::vector<uint8_t> buf(block_size);
    uint64_t lb = 0;
    uint64_t processed = 0;
    while (processed < size) {
        uint64_t pb = 0;
        if (!get_file_block(inode, lb, pb) || pb == 0) { lb++; processed += block_size; continue; }
        if (!read_block(pb, buf.data())) return false;
        uint32_t off = 0;
        while (off < block_size && processed + off < size) {
            auto* de = (ext4_dir_entry_2*)(buf.data() + off);
            if (de->rec_len < 8) break;
            if (de->inode != 0 && de->name_len > 0) {
                std::string name(de->name, de->name_len);
                if (name != "." && name != "..") {
                    extract_inode(de->inode, outPath + "/" + name, depth + 1);
                }
            }
            off += de->rec_len;
        }
        lb++; processed += block_size;
    }
    return true;
}

bool Ext4::extract_inode(uint32_t ino, const std::string& outPath, int depth) {
    ext4_inode in{};
    if (!read_inode(ino, in)) return false;
    uint16_t mode = in.i_mode;
    uint16_t type = mode & 0170000;
    if (type == 0040000) { // dir
        __android_log_print(ANDROID_LOG_INFO, TAG, "dir: %s", outPath.c_str());
        return extract_dir(in, outPath, depth);
    } else if (type == 0100000) { // regular
        return extract_file(in, outPath);
    } else if (type == 0120000) { // symlink
        return extract_symlink(in, outPath);
    } else {
        // char/block/fifo/socket - skip or create minimal
        return true;
    }
}

bool ext4_extract_image(const std::string& imgPath, const std::string& outDir, std::string& err) {
    Ext4 e;
    if (!e.open(imgPath)) { err = "Failed to open/parse ext4 image: " + imgPath; return false; }
    ensure_dir(outDir);
    bool ok = e.extract_inode(2 /*EXT4_ROOT_INO*/, outDir, 0);
    e.close();
    if (!ok) { err = "Extraction failed (partial)"; return false; }
    return true;
}