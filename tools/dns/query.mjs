#!/usr/bin/env node
// Minimal DNS query tool for the Lagran DNS integration test.
//
//   node tools/dns/query.mjs <host> <port> <name> [type] [ecs-cidr] [--tcp]
//
// Prints JSON: { rcode, tc, answers: [{type, ttl, ip}], soa: bool }

import dgram from 'node:dgram'
import net from 'node:net'

const args = process.argv.slice(2)
const tcp = args.includes('--tcp')
const rest = args.filter((a) => a !== '--tcp')
const [host, portStr, name, typeArg = 'A', ecsArg = ''] = rest
const port = Number(portStr)
if (!host || !port || !name) {
  console.error('usage: query.mjs <host> <port> <name> [A|AAAA|SOA|NS|ANY] [ecs-cidr] [--tcp]')
  process.exit(2)
}

const TYPE = { A: 1, NS: 2, SOA: 6, AAAA: 28, ANY: 255 }
const qtype = TYPE[typeArg.toUpperCase()] ?? Number(typeArg)
if (!qtype) {
  console.error(`unsupported type: ${typeArg}`)
  process.exit(2)
}

function encodeName(out, name) {
  for (const label of name.replace(/\.$/, '').split('.')) {
    if (!label) continue
    const b = Buffer.from(label, 'ascii')
    out.push(b.length)
    out.push(...b)
  }
  out.push(0)
}

function parseEcs(cidr) {
  if (!cidr) return null
  const [ip, prefixStr] = cidr.split('/')
  const prefix = Number(prefixStr ?? (ip.includes(':') ? 128 : 32))
  const isV4 = !ip.includes(':')
  const bytes = isV4
    ? ip.split('.').map((x) => Number(x))
    : (() => {
        // Only used for v6 tests; use Node's URL to normalize.
        const u = new URL(`http://[${ip}]/`)
        const bin = Buffer.from(u.hostname.replace(/^\[|\]$/g, '').split(':').flatMap((h) => {
          if (!h) return [0, 0]
          return [parseInt(h.slice(0, 2), 16), parseInt(h.slice(2), 16)]
        }))
        return [...bin]
      })()
  const family = isV4 ? 1 : 2
  const mask = (arr, bits) => {
    const out = [...arr]
    for (let i = 0; i < out.length; i++) {
      const remaining = bits - i * 8
      const m = remaining >= 8 ? 255 : remaining <= 0 ? 0 : (255 << (8 - remaining)) & 255
      out[i] &= m
    }
    return out
  }
  return { family, prefix, addr: mask(bytes, prefix) }
}

function buildQuery() {
  const id = Math.floor(Math.random() * 65535)
  const ecs = parseEcs(ecsArg)
  const out = []
  const u16 = (n) => out.push((n >> 8) & 255, n & 255)
  const u32 = (n) => out.push((n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255)
  u16(id)
  u16(0) // flags: standard query
  u16(1) // QD
  u16(0)
  u16(0)
  u16(ecs ? 1 : 0)
  encodeName(out, name)
  u16(qtype)
  u16(1) // IN
  if (ecs) {
    out.push(0) // root
    u16(41) // OPT
    u16(1232)
    u32(0)
    const rdata = []
    const ru16 = (n) => rdata.push((n >> 8) & 255, n & 255)
    ru16(8)
    ru16(4 + ecs.addr.length)
    ru16(ecs.family)
    rdata.push(ecs.prefix)
    rdata.push(0)
    rdata.push(...ecs.addr)
    u16(rdata.length)
    out.push(...rdata)
  }
  return Buffer.from(out)
}

function readName(buf, start) {
  let pos = start
  let end = start
  let jumped = false
  const labels = []
  let hops = 0
  for (;;) {
    if (pos >= buf.length) throw new Error('bad name')
    const len = buf[pos]
    if (len === 0) {
      if (!jumped) end = pos + 1
      return [labels.join('.'), end]
    }
    if ((len & 0xc0) === 0xc0) {
      const ptr = ((len & 0x3f) << 8) | buf[pos + 1]
      if (!jumped) end = pos + 2
      jumped = true
      pos = ptr
      if (++hops > 32) throw new Error('name loop')
      continue
    }
    const l = len
    labels.push(buf.subarray(pos + 1, pos + 1 + l).toString('ascii'))
    pos += 1 + l
  }
}

function parseResponse(buf) {
  const id = buf.readUInt16BE(0)
  const flags = buf.readUInt16BE(2)
  const qd = buf.readUInt16BE(4)
  const an = buf.readUInt16BE(6)
  const ns = buf.readUInt16BE(8)
  let pos = 12
  for (let i = 0; i < qd; i++) {
    ;[, pos] = readName(buf, pos)
    pos += 4
  }
  const answers = []
  let soa = false
  for (let i = 0; i < an; i++) {
    ;[, pos] = readName(buf, pos)
    const rtype = buf.readUInt16BE(pos)
    const ttl = buf.readUInt32BE(pos + 4)
    const rdlen = buf.readUInt16BE(pos + 8)
    const rdata = buf.subarray(pos + 10, pos + 10 + rdlen)
    pos += 10 + rdlen
    if (rtype === 1 && rdlen === 4) {
      answers.push({ type: 'A', ttl, ip: [...rdata].join('.') })
    } else if (rtype === 28 && rdlen === 16) {
      const hex = [...rdata].map((b) => b.toString(16).padStart(2, '0')).join('')
      const parts = []
      for (let j = 0; j < 16; j += 2) parts.push(hex.slice(j * 2, j * 2 + 4))
      answers.push({ type: 'AAAA', ttl, ip: parts.join(':') })
    } else if (rtype === 6) {
      soa = true
    } else {
      answers.push({ type: rtype, ttl })
    }
  }
  for (let i = 0; i < ns; i++) {
    ;[, pos] = readName(buf, pos)
    const rtype = buf.readUInt16BE(pos)
    const rdlen = buf.readUInt16BE(pos + 8)
    pos += 10 + rdlen
    if (rtype === 6) soa = true
  }
  return {
    id,
    rcode: flags & 0x000f,
    tc: (flags & 0x0200) !== 0,
    answers,
    soa,
  }
}

function udpQuery(packet) {
  return new Promise((resolve, reject) => {
    const sock = dgram.createSocket('udp4')
    const timer = setTimeout(() => {
      sock.close()
      reject(new Error('dns timeout'))
    }, 3000)
    sock.on('message', (msg) => {
      clearTimeout(timer)
      sock.close()
      resolve(msg)
    })
    sock.on('error', (e) => {
      clearTimeout(timer)
      sock.close()
      reject(e)
    })
    sock.send(packet, port, host)
  })
}

function tcpQuery(packet) {
  return new Promise((resolve, reject) => {
    const sock = net.createConnection({ host, port }, () => {
      const len = Buffer.alloc(2)
      len.writeUInt16BE(packet.length, 0)
      sock.write(Buffer.concat([len, packet]))
    })
    const chunks = []
    sock.on('data', (c) => chunks.push(c))
    sock.on('end', () => {
      const all = Buffer.concat(chunks)
      if (all.length < 2) return reject(new Error('short tcp response'))
      const len = all.readUInt16BE(0)
      resolve(all.subarray(2, 2 + len))
    })
    sock.on('error', reject)
    setTimeout(() => {
      sock.destroy()
      reject(new Error('tcp timeout'))
    }, 3000)
  })
}

const packet = buildQuery()
const resp = tcp ? await tcpQuery(packet) : await udpQuery(packet)
console.log(JSON.stringify(parseResponse(resp)))
