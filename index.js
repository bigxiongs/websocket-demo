const http = require("http");
const crypto = require("crypto");

const server = http.createServer((req, res) => {
  res.writeHead(200, { "Content-Type": "text/plain" });
  res.end("okay");
});

server.on("upgrade", (req, socket) => {
  socket.write(
    "HTTP/1.1 101 Web Socket Protocol Handshake\r\n" +
      "Upgrade: WebSocket\r\n" +
      "Connection: Upgrade\r\n" +
      `Sec-Websocket-Accept: ${setWebsocketAccept(
        req.headers["sec-websocket-key"]
      )}\r\n` +
      "\r\n"
  );
  socket.on("data", (buffer) => {
    const message = parseMessage(buffer);
    if (message) {
      console.log(message);
      socket.write(constructReply("Hello from the server!"));
    } else if (message === null) {
      console.log("WebSocket connection closed");
      socket.end();
    }
  });
});

server.listen(8000);

const setWebsocketAccept = (setWebsocketKey) =>
  crypto
    .createHash("sha1")
    .update(setWebsocketKey + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11", "binary")
    .digest("base64");

const parseMessage = (buffer) => {
  const B1 = buffer.readUInt8(0);
  const FIN = (B1 >>> 7) & 0x1;
  const [R1, R2, R3] = [(B1 >>> 6) & 0x1, (B1 >>> 5) & 0x1, (B1 >>> 4) & 0x1];
  const opcode = B1 & 0xf;
  if (opcode === 0x8) return null;
  if (opcode !== 0x1) return;

  const B2 = buffer.readUInt8(1);
  const isMasked = Boolean((B2 >>> 7) & 0x1);
  let offset = 2;
  let payloadLength = B2 & 0x7f;

  if (payloadLength === 126) {
    payloadLength = buffer.readUInt16BE(offset);
    offset += 2;
  } else if (payloadLength === 127) return null;

  const data = Buffer.alloc(payloadLength);
  if (!isMasked) {
    buffer.copy(data, 0, offset);
    return data.toString("utf-8");
  }
  const mask = [0, 1, 2, 3].map((i) => buffer.readUInt8(offset + i));
  offset += 4;

  for (let i = 0, j = 0; i < payloadLength; ++i, j = i % 4) {
    const source = buffer.readUInt8(offset++);
    data.writeUInt8(mask[j] ^ source, i);
  }
  return data.toString("utf-8");
};

const constructReply = (data, opcode = 0b0001) => {
  const dataByteLength = Buffer.byteLength(data);

  const lengthByteCount = dataByteLength < 126 ? 0 : 2;
  const payloadLength = lengthByteCount === 0 ? dataByteLength : 126;
  const buffer = Buffer.alloc(2 + lengthByteCount + dataByteLength);

  buffer.writeUInt8(0b10000000 | opcode, 0);
  buffer.writeUInt8(payloadLength, 1);

  let payloadOffset = 2;
  if (lengthByteCount > 0) {
    buffer.writeUInt16BE(dataByteLength, 2);
    payloadOffset += lengthByteCount;
  }

  buffer.write(data, payloadOffset);
  return buffer;
};
