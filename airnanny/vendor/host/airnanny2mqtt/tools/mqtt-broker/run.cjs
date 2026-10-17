// Real MQTT3.1.1 broker with in-memory persistence; test lifecycle only.
const fs = require('node:fs');
const net = require('node:net');
const aedes = require('aedes');
const path = process.argv[2];
const config = JSON.parse(fs.readFileSync(path, 'utf8'));
if (config.host !== '127.0.0.1' || !Number.isInteger(config.port) || config.port < 1024) {
  throw new Error('Test listener must be loopback on an unprivileged port');
}
const logfile = path.replace(/\.json$/, '.log');
let logBytes = 0;
function log(event) {
  const line = JSON.stringify({event}) + '\n';
  if (logBytes + line.length > 131072) return;
  fs.appendFileSync(logfile, line);
  logBytes += line.length;
}
fs.writeFileSync(logfile, '');
const broker = aedes({heartbeatInterval: 60000});
broker.on('clientError', () => log('client_error'));
broker.on('connectionError', () => log('connection_error'));
broker.on('client', () => log('connect'));
broker.on('clientDisconnect', () => log('disconnect'));
const server = net.createServer(broker.handle);
server.maxConnections = 16;
server.listen(config.port, config.host, () => {
  log('ready');
  fs.writeFileSync(path.replace(/\.json$/, '.ready'), 'ready');
});
server.on('error', () => { log('listener_error'); process.exit(1); });
