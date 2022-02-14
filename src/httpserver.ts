import express = require('express')
import request = require('superagent')
import fs = require('fs')
const Rabin = require('./rabin/rabin')

const app = express()

let curBlockData = {}

const allowCors = function (req, res, next) {
    res.header('Access-Control-Allow-Origin', req.headers.origin);
    res.header('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS');
    res.header('Access-Control-Allow-Headers', ['Content-Type', 'Content-Encoding']);
    res.header('Access-Control-Allow-Credentials', 'true');
    next();
};
app.use(allowCors)

const server: any = {}

server.app = app

let httpserver

//const TIMEOUT = 30000 // 30s
const PUBKEY_LEN = 384

const symbol = 'BSV_USDC'
const symbolBuf = Buffer.alloc(16, 0)
symbolBuf.write(symbol)

function getUInt8Buf(amount) {
    const buf = Buffer.alloc(1, 0)
    buf.writeUInt8(amount)
    return buf
}

function getUInt32Buf(amount: number) {
    const buf = Buffer.alloc(4, 0)
    buf.writeUInt32LE(amount)
    return buf
}

function getUInt64Buf(amount) {
    const buf = Buffer.alloc(8, 0)
    buf.writeBigUInt64LE(BigInt(amount))
    return buf
}

function toBufferLE(num: BigInt, width: number) {
    const hex = num.toString(16);
    const buffer = Buffer.from(hex.padStart(width * 2, '0').slice(0, width * 2), 'hex');
    buffer.reverse();
    return buffer;
}

async function getBsvPrice(source: string) {
    //TODO
    return 10000
}

server.start = function (config) {

    if (!process.env.RABIN_P || !process.env.RABIN_Q) {
        throw Error('need rabin private key in env')
    }

    const rabinPrivateKey = {
        p: BigInt(process.env.RABIN_P),
        q: BigInt(process.env.RABIN_Q)
    }
    const rabinPubKey = Rabin.privKeyToPubKey(rabinPrivateKey.p, rabinPrivateKey.q)
    const rabinPubKeyhex = toBufferLE(rabinPubKey, PUBKEY_LEN).toString('hex')

    app.get('/', async function(req, res) {
        let price = await getBsvPrice(config.source)
        price = Math.floor(price * 10000)
        /*if (price === false) {
            console.log('getBsvPrice failed: ',res, res.body)
            res.json({code: 1, msg: 'getBsvPrice failed'})
            return
        }*/

        let userdata = Buffer.alloc(0)
        if (req.query.nonce) {
            userdata = Buffer.from(req.query.nonce, 'hex')
        }
        const timestamp = Math.floor(new Date().getTime() / 1000)
        const rabinMsg = Buffer.concat([
            getUInt32Buf(timestamp),
            getUInt64Buf(price),
            getUInt8Buf(4),
            symbolBuf,
            userdata,
        ])

        let rabinSignResult = Rabin.sign(rabinMsg.toString('hex'), rabinPrivateKey.p, rabinPrivateKey.q, rabinPubKey)
        const rabinSign = toBufferLE(rabinSignResult.signature, PUBKEY_LEN).toString('hex')
        const rabinPadding = Buffer.alloc(rabinSignResult.paddingByteCount, 0).toString('hex')

        const data = {
            "symbol":symbol,
            "rate": price,
            "timestamp": Math.floor(new Date().getTime() / 1000),
            "digest": rabinMsg.toString('hex'),
            "signatures":{
                "rabin":{
                    "public_key": rabinPubKey.toString(),
                    "signature": rabinSign,
                    "padding": rabinPadding,
                }
            }
        }
        res.json(data)
    })

    httpserver = app.listen(config.port, config.ip, function () {
        console.log("start at listen %s, %s:%s", config.source, config.ip, config.port)
    })
}

server.closeFlag = false

server.close = async function () {
    server.closeFlag = true
    await httpserver.close()
}

async function main() {
    const path = process.argv[2]
    const config = JSON.parse(fs.readFileSync(path).toString())
    server.start(config)
}

main()