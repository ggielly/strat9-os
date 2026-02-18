use crc32c::crc32c;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use xfs_rs::crc::*;
fn bench_crc_implementations(c: &mut Criterion) {
    let sizes = [64, 256, 512, 1024, 4096, 16384, 65536];

    let mut group = c.benchmark_group("CRC32C");

    for size in sizes {
        // Use realistic XFS-like data (mix of bytes)
        let data: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
        group.throughput(Throughput::Bytes(size as u64));

        // crc32c crate direct
        group.bench_with_input(BenchmarkId::new("crc32c_crate", size), &data, |b, d| {
            b.iter(|| crc32c(black_box(d)))
        });

        // XFS API (wrapper around crc32c)
        group.bench_with_input(BenchmarkId::new("xfs_crc32c", size), &data, |b, d| {
            b.iter(|| xfs_crc32c(black_box(d)))
        });
    }

    group.finish();
}

fn bench_xfs_structures(c: &mut Criterion) {
    let mut group = c.benchmark_group("XFS Structures");

    // Superblock (512 bytes)
    let superblock = [0x58u8; 512]; // 'X' pattern
    group.throughput(Throughput::Bytes(512));
    group.bench_function("superblock_512", |b| {
        b.iter(|| superblock_crc(black_box(&superblock)))
    });

    // Fixed-size superblock (standard API)
    group.bench_function("superblock_fixed_512", |b| {
        b.iter(|| superblock_crc(black_box(&superblock)))
    });

    // Inode (256 bytes typical)
    let inode = [0u8; 256];
    group.throughput(Throughput::Bytes(256));
    group.bench_function("inode_256", |b| b.iter(|| inode_crc(black_box(&inode))));

    group.finish();
}

#[cfg(feature = "std")]
fn bench_runtime_detection(c: &mut Criterion) {
    let data = vec![0x42u8; 4096];

    c.bench_function("runtime_detect_4k", |b| {
        b.iter(|| xfs_crc32c(black_box(&data)))
    });
}

#[cfg(feature = "std")]
criterion_group!(
    benches,
    bench_crc_implementations,
    bench_xfs_structures,
    bench_runtime_detection
);

#[cfg(not(feature = "std"))]
criterion_group!(benches, bench_crc_implementations, bench_xfs_structures);

criterion_main!(benches);
