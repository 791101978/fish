/**
 * 摸鱼垂钓 · 静态托管服务端
 * 账号体系与存档已迁移至 WorkBuddy 云服务（Auth + Database，RLS 隔离），
 * 本服务只负责把游戏页面发出去，不再自建账号接口。
 *   - 仅对外暴露 fishing-game.html 一个文件，杜绝 server.js / package.json 等源码外泄
 *   - 云服务数据面路径（/.cloud/**）由平台网关接管，与本服务无关
 * 启动：node server.js      (PORT 环境变量可选，默认 3000)
 */
'use strict';

const http = require('http');
const fs = require('fs');
const path = require('path');

const ROOT = __dirname;
const PORT = Number(process.env.PORT) || 3000;
const ENTRY = 'fishing-game.html';

const server = http.createServer((req, res) => {
  let urlPath;
  try { urlPath = new URL(req.url, 'http://localhost').pathname; }
  catch (e) { res.writeHead(400, { 'Content-Type': 'text/plain; charset=utf-8' }); return res.end('400 Bad Request'); }

  if (urlPath === '/' || urlPath === '/index.html') {
    return fs.readFile(path.join(ROOT, ENTRY), (err, buf) => {
      if (err) {
        console.error('[entry]', ENTRY, '读取失败');
        res.writeHead(500, { 'Content-Type': 'text/plain; charset=utf-8' });
        return res.end('entry missing');
      }
      res.writeHead(200, {
        'Content-Type': 'text/html; charset=utf-8',
        'Content-Length': buf.length,
        'Cache-Control': 'no-cache',
      });
      res.end(buf);
    });
  }

  res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
  res.end('404 Not Found');
});

server.on('clientError', (err, socket) => {
  try { socket.end('HTTP/1.1 400 Bad Request\r\n\r\n'); } catch (e) {}
});

process.on('uncaughtException', e => console.error('[uncaught]', e && e.stack || e));

server.listen(PORT, '0.0.0.0', () => {
  console.log('');
  console.log('  🎣 摸鱼垂钓 · 页面服务已启动');
  console.log('  ────────────────────────────────');
  console.log('  地址：http://localhost:' + PORT);
  console.log('  账号 / 存档：WorkBuddy 云服务');
  console.log('');
});
