package logevent

// CacheHit is emitted on a cache hit; attr backend identifies the tier:
// memory, dynamodb, s3, local (Debug).
var CacheHit = newEvent("cache.hit")

// CacheMiss is emitted on a cache miss; attr backend identifies the tier
// (Debug).
var CacheMiss = newEvent("cache.miss")

// CacheExpired is emitted when a cache entry is found but expired; attr
// backend identifies the tier (Debug).
var CacheExpired = newEvent("cache.expired")

// CacheSet is emitted when a cache entry is written; attr backend identifies
// the tier (Debug).
var CacheSet = newEvent("cache.set")

// CacheEvict is emitted when a cache entry is evicted; attr backend
// identifies the tier (Debug).
var CacheEvict = newEvent("cache.evict")

// CacheReadFailure is emitted when a cache read fails; attr backend
// identifies the tier (Error).
var CacheReadFailure = newEvent("cache.read.failure")

// CacheWriteFailure is emitted when a cache write fails; attr backend
// identifies the tier (Error).
var CacheWriteFailure = newEvent("cache.write.failure")

// CacheItemOversize is emitted when a cache item exceeds its size bound;
// attr backend identifies the tier (Warn).
var CacheItemOversize = newEvent("cache.item.oversize")

// CacheItemInvalid is emitted when a cache item fails validation; attr
// backend identifies the tier (Error).
var CacheItemInvalid = newEvent("cache.item.invalid")

// CacheCleanupFailure is emitted when cache cleanup fails; attr backend
// identifies the tier (Warn).
var CacheCleanupFailure = newEvent("cache.cleanup.failure")
