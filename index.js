var AJV = require('ajv')
var Duplexify = require('duplexify')
var assert = require('nanoassert')
var inherits = require('inherits')
var lengthPrefixedStream = require('length-prefixed-stream')
var sodium = require('sodium-universal')
var through2 = require('through2')

var STREAM_NONCEBYTES = sodium.crypto_stream_NONCEBYTES
var STREAM_KEYBYTES = sodium.crypto_stream_KEYBYTES

var HANDSHAKE_PREFIX = 0

module.exports = function (options) {
  assert(typeof options === 'object', 'argument must be an Object')

  var version = options.version
  assert(typeof version === 'number', 'version must be a Number')
  assert(version > 0, 'version must be greater than zero')
  assert(Number.isSafeInteger(version), 'version must be safe integer')

  var messages = options.messages
  assert(typeof messages === 'object', 'messages must be an Object')
  var messageNames = Object.keys(messages)
  assert(messageNames.length !== 0, 'messages must have properties')

  var ajv = new AJV()
  var messageTypesByName = {}
  var messageTypesByPrefix = {}
  var messageTypePrefixes = [0]
  messageNames.sort().forEach(function (name, index) {
    var options = messages[name]
    assert(options.hasOwnProperty('schema'), 'message type must have schema')
    if (options.hasOwnProperty('verify')) {
      assert(
        typeof options.verify === 'function',
        'verify must be a Function'
      )
    }
    var schema = options.schema
    var valid = ajv.compile(schema)
    var prefix = index + 1 // Reserve prefix 0 for handshakes.
    messageTypePrefixes.push(prefix)
    messageTypesByName[name] = messageTypesByPrefix[prefix] = {
      name: name,
      valid: valid,
      verify:
        options.verify ||
        function () {
          return true
        },
      prefix: prefix
    }
    Protocol.prototype[name] = function (data, callback) {
      this._sendMessage(name, data, callback)
    }
  })

  var validTuple = ajv.compile({
    title: 'Protocol Message',
    type: 'array',
    items: [
      {
        title: 'Message Type Prefix',
        type: 'number',
        enum: messageTypePrefixes
      },
      {
        title: 'Message Payload'
        /* anything */
      }
    ],
    additionalItems: false
  })

  var validHandshake = ajv.compile({
    title: 'Handshake Message',
    type: 'object',
    properties: {
      version: {
        title: 'Protocol Version',
        type: 'number',
        multipleOf: 1,
        minimum: 1
      },
      nonce: {
        title: 'Encryption Nonce',
        type: 'string',
        pattern: '^[a-f0-9]{' + STREAM_NONCEBYTES * 2 + '}$'
      }
    },
    required: ['version', 'nonce'],
    additionalProperties: false
  })

  function Protocol (options) {
    assert(typeof options === 'object', 'argument must be an Object')

    if (!(this instanceof Protocol)) return new Protocol(options)

    var key = (this._key = options.key)
    assert(Buffer.isBuffer(key), 'key must be a Buffer')
    assert(
      key.byteLength === STREAM_KEYBYTES,
      'key must be crypto_stream_KEYBYTES long'
    )

    this._initializeReadable()
    this._initializeWritable()
    Duplexify.call(this, this._writableStream, this._readableStream)
  }

  Protocol.prototype._initializeReadable = function () {
    var self = this

    // Cryptographic stream using our nonce and the secret key.
    self._sendingNonce = Buffer.alloc(STREAM_NONCEBYTES)
    sodium.randombytes_buf(self._sendingNonce)
    self._sendingCipher = initializeCipher(
      self._sendingNonce,
      self._key
    )

    self._encoderStream = lengthPrefixedStream.encode()

    self._readableStream = through2.obj(function (chunk, _, done) {
      assert(Buffer.isBuffer(chunk), 'chunk must be a Buffer')
      // Once we've sent our nonce, encrypt.
      if (self._sentNonce) {
        self._sendingCipher.update(chunk, chunk)
      }
      this.push(chunk)
      done()
    })

    self._encoderStream
      .pipe(self._readableStream)
      .once('error', function (error) {
        self.destroy(error)
      })
  }

  Protocol.prototype._initializeWritable = function () {
    var self = this

    // Cryptographic stream using our peer's nonce, which we've yet
    // to receive, and the secret key.
    self._receivingNonce = null
    self._receivingCipher = null

    self._writableStream = through2(function (chunk, encoding, done) {
      assert(Buffer.isBuffer(chunk), 'chunk must be a Buffer')
      // Once we've been given a nonce, decrypt.
      if (self._receivingCipher) {
        self._receivingCipher.update(chunk, chunk)
      }
      // Until we've been given a nonce, write in the clear.
      done(null, chunk)
    })

    self._parserStream = through2.obj(function (chunk, _, done) {
      self._parse(chunk, function (error) {
        if (error) return done(error)
        done()
      })
    })

    self._writableStream
      .pipe(lengthPrefixedStream.decode())
      .pipe(self._parserStream)
      .once('error', function (error) {
        self.destroy(error)
      })
  }

  // Send our handshake message.
  Protocol.prototype.handshake = function (callback) {
    assert(typeof callback === 'function', 'callback must be a Function')
    var self = this
    if (self._sentNonce) return callback(new Error('already sent handshake'))
    self._encode(
      HANDSHAKE_PREFIX,
      {
        version: version,
        nonce: self._sendingNonce.toString('hex')
      },
      function (error) {
        if (error) return callback(error)
        self._sentNonce = true
        callback()
      }
    )
  }

  // Send a protocol-defined message.
  //
  // The constructor adds functions to the prototype for sending each
  // message type, which call this function in turn.
  Protocol.prototype._sendMessage = function (typeName, data, callback) {
    assert(
      messageTypesByName.hasOwnProperty(typeName),
      'unknown message type: ' + typeName
    )
    assert(typeof callback === 'function', 'callback must be a Function')
    var type = messageTypesByName[typeName]
    try {
      assert(type.valid(data))
      assert(type.verify(data))
    } catch (error) {
      var moreInformativeError = new Error('invalid ' + typeName)
      moreInformativeError.errors = type.valid.errors
      throw moreInformativeError
    }
    this._encode(type.prefix, data, callback)
  }

  Protocol.prototype.finalize = function (callback) {
    assert(typeof callback === 'function', 'callback must be a Function')
    var self = this
    self._finalize(function (error) {
      if (error) return self.destroy(error)
      self._encoderStream.end(callback)
      self._sendingCipher.final()
      self._sendingCipher = null
      self._receivingCipher.final()
      self._receivingCipher = null
    })
  }

  Protocol.prototype._encode = function (prefix, body, callback) {
    var tuple = [prefix, body]
    var buffer = Buffer.from(JSON.stringify(tuple), 'utf8')
    this._encoderStream.write(buffer, callback)
  }

  Protocol.prototype._parse = function (message, callback) {
    try {
      var parsed = JSON.parse(message)
    } catch (error) {
      return callback(error)
    }
    if (!validTuple(parsed)) {
      return callback(new Error('invalid tuple'))
    }
    var prefix = parsed[0]
    var body = parsed[1]
    if (prefix === 0 && validHandshake(body)) {
      if (version !== body.version) {
        var error = new Error('version mismatch')
        error.version = body.version
        return callback(error)
      }
      if (!this._receivingCipher) {
        this._receivingNonce = Buffer.from(body.nonce, 'hex')
        assert(
          this._receivingNonce.byteLength === STREAM_NONCEBYTES,
          'receiving nonce must be STREAM_NONCEBYTES long'
        )
        this._receivingCipher = initializeCipher(
          this._receivingNonce,
          this._key
        )
        this.emit('handshake')
        return callback()
      }
      this.emit('handshake')
      return callback()
    }
    var type = messageTypesByPrefix[prefix]
    if (!type || !type.valid(body) || !type.verify(body)) {
      this.emit('invalid', body)
      return callback()
    }
    this.emit(type.name, body)
    return callback()
  }

  inherits(Protocol, Duplexify)

  return Protocol
}

function initializeCipher (nonce, secretKey) {
  assert(Buffer.isBuffer(nonce), 'nonce must be a Buffer')
  assert(
    nonce.byteLength === STREAM_NONCEBYTES,
    'nonce must be STREAM_NONCEBYTES long'
  )
  assert(Buffer.isBuffer(secretKey), 'secretKey must be a Buffer')
  assert(
    secretKey.byteLength === STREAM_KEYBYTES,
    'secretKey must be STREAM_KEYBYTES long'
  )
  return sodium.crypto_stream_xor_instance(nonce, secretKey)
}
