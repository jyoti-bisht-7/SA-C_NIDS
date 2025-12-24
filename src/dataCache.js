// Simple in-memory cache for fetched UI data to avoid refetching on route changes
const cache = new Map()

export function getCached(key) {
  return cache.has(key) ? cache.get(key) : undefined
}

export function setCached(key, value) {
  cache.set(key, value)
}

export function clearCached(key) {
  if (key) cache.delete(key)
  else cache.clear()
}

export default { getCached, setCached, clearCached }
