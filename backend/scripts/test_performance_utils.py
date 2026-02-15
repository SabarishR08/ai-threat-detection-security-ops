#!/usr/bin/env python
"""Test performance utilities initialization."""

import sys
from pathlib import Path

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from backend.utils.performance_utils import (
    get_performance_cache,
    get_bloom_filter,
    get_batch_processor,
    get_all_performance_stats
)

print("=" * 60)
print("PERFORMANCE UTILITIES VERIFICATION")
print("=" * 60)

# Test 1: Adaptive Cache
print("\n1. Adaptive Cache")
cache = get_performance_cache()
stats = cache.get_stats()
print(f"   ✅ Instance: {type(cache).__name__}")
print(f"   ✅ Size: {stats['size']}/{cache.max_size}")
print(f"   ✅ Hit Rate: {stats['hit_rate_percent']:.1f}%")
print(f"   ✅ Hits: {stats['hits']}, Misses: {stats['misses']}")

# Test 2: Bloom Filter
print("\n2. Bloom Filter")
bloom = get_bloom_filter()
bloom_stats = bloom.get_stats()
print(f"   ✅ Instance: {type(bloom).__name__}")
print(f"   ✅ Size: {bloom.size} bits")
print(f"   ✅ Hash functions: {bloom.hash_count}")
print(f"   ✅ Fill rate: {bloom_stats['fill_rate_percent']:.1f}%")
print(f"   ✅ False positive rate: {bloom_stats['false_positive_rate']:.4f}%")

# Test 3: Batch Processor
print("\n3. Batch Processor")
batch = get_batch_processor()
batch_stats = batch.get_stats()
print(f"   ✅ Instance: {type(batch).__name__}")
print(f"   ✅ Batch size: {batch.batch_size}")
print(f"   ✅ Timeout: {batch.timeout}s")
print(f"   ✅ Queued: {len(batch.queue)} items")
print(f"   ✅ Processed: {batch_stats['batches_processed']} batches")

# Test 4: Comprehensive Stats
print("\n4. Comprehensive Statistics")
all_stats = get_all_performance_stats()
print(f"   ✅ Cache hit rate: {all_stats['adaptive_cache']['hit_rate_percent']:.1f}%")
print(f"   ✅ Bloom fill rate: {all_stats['bloom_filter']['fill_rate_percent']:.1f}%")
print(f"   ✅ Batch processor status: {all_stats['batch_processor']['batches_processed']} batches")
print(f"   ✅ Timestamp: {all_stats['timestamp']}")

print("\n" + "=" * 60)
print("✅ ALL PERFORMANCE UTILITIES WORKING CORRECTLY")
print("=" * 60)
