// Usage: node recording-mock.mjs <port-file> <log-file>

import fs from 'node:fs';
import http from 'node:http';
import { createGate } from './gate-fake.mjs';

const [portFile, logFile] = process.argv.slice(2);
const mock = createGate();
const upstream = new URL(await mock.listen(0, '127.0.0.1'));

const proxy = http.createServer((req, res) => {
  const chunks = [];
  req.on('data', (chunk) => chunks.push(chunk));
  req.on('end', () => {
    const body = Buffer.concat(chunks);
    const forward = http.request(
      { hostname: upstream.hostname, port: upstream.port, path: req.url, method: req.method, headers: req.headers },
      (up) => {
        const out = [];
        up.on('data', (chunk) => out.push(chunk));
        up.on('end', () => {
          const response = Buffer.concat(out);
          fs.appendFileSync(
            logFile,
            JSON.stringify({
              url: req.url,
              status: up.statusCode,
              headers: req.headers,
              body: body.toString('base64'),
              response: response.toString('utf8'),
            }) + '\n'
          );
          res.writeHead(up.statusCode, up.headers);
          res.end(response);
        });
      }
    );
    forward.on('error', (error) => {
      res.writeHead(502);
      res.end(String(error));
    });
    forward.end(body);
  });
});

proxy.listen(0, '127.0.0.1', () => fs.writeFileSync(portFile, String(proxy.address().port)));
