const Redis = require('ioredis')
const db = require('./db')

const redis = new Redis(process.env.REDIS_URL || 'redis://127.0.0.1:6379')

async function processEvent(obj) {
  switch (obj.type) {
    case 'alert':
      await new Promise(resolve => db.insertAlert(obj.data, (err) => {
        if (err) console.error('DB alert insert error:', err)
        resolve()
      }))
      break
    case 'audit':
      await new Promise(resolve => db.insertAudit(obj.data.message, () => resolve()))
      break
    case 'event':
      await new Promise(resolve => db.insertEvent(obj.data, (err) => {
        if (err) console.error('DB event insert error:', err)
        resolve()
      }))
      break
    default:
      await new Promise(resolve => db.insertAudit(JSON.stringify(obj), () => resolve()))
  }
}

async function runWorker() {
  console.log('Worker started, dynamically processing Redis events...')
  while (true) {
    try {
      const res = await redis.brpop('events', 0)
      if (!res) continue
      const payload = res[1]
      const obj = JSON.parse(payload)
      await processEvent(obj)
    } catch (e) {
      console.error('Worker loop error:', e)
      await new Promise(r => setTimeout(r, 1000))
    }
  }
}

process.on('SIGINT', () => {
  console.log('Gracefully shutting down worker...')
  redis.quit()
  process.exit(0)
})

runWorker().catch(e => console.error('Worker failed to start:', e))