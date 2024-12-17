const express = require('express');
const fs = require('fs');
const https = require('https');
const proxy = require('http-proxy');
const url = require('url');

const api = require('./api.js');
const blocked = require('./static/blocked.json');
const reBlocked = require('./static/re_blocked.json');

const DOMAIN = process.env.DOMAIN || "localhost";
const PORT = process.env.PORT || 80;
const HTTPS_PORT = process.env.HTTPS_PORT || 443;
const SECRET_KEY = process.env.SECRET_KEY;
const SUBDOMAIN_AS_PATH = true;

const httpsProxy = proxy.createProxyServer({
  agent: new https.Agent({
    checkServerIdentity: function (host, cert) {
      return undefined;
    }
  }),
  changeOrigin: true
});

const httpProxy = proxy.createProxyServer({
  changeOrigin: true
});

function stripSub(link) {
  const original = url.parse(link);
  let sub = '';
  let path = original.path;
  if (SUBDOMAIN_AS_PATH) {
    const split = path.split('/');
    sub = split[1] ? split[1] + '.' : '';
    split.splice(1, 1);
    path = split.join('/');
  }
  return [path || '/', sub];
}

function getSubdomain(req, rewrite) {
  let sub;
  if (SUBDOMAIN_AS_PATH) {
    const res = stripSub(req.url);
    if (rewrite) {
      req.url = res[0];
    }
    sub = res[1];
  } else {
    const hostDomain = req.headers.host;
    sub = hostDomain.slice(0, hostDomain.lastIndexOf('.', hostDomain.lastIndexOf('.') - 1) + 1);
  }
  return sub;
}

function onProxyError(err, req, res) {
  console.error(err);

  res.writeHead(500, {
    'Content-Type': 'text/plain'
  });

  res.end('Proxying failed.');
}

function onProxyReq(proxyReq, req, res, options) {
  proxyReq.setHeader('User-Agent', 'RobloxStudio/Darwin RobloxApp/0.654.1.6540477 (GlobalDist; RobloxDirectDownload)');
  proxyReq.setHeader('Roblox-Game-Id', '00000000-0000-0000-0000-000000000000')
  proxyReq.setHeader('Roblox-Place-Id', '0')
  proxyReq.setHeader('Roblox-Universe-Id', '0')
  proxyReq.setHeader('PlayerCount', '1')
  proxyReq.setHeader('Requester', 'Client')
  const cookie = proxyReq.getHeader('Cookie')
  if (cookie) {
    proxyReq.setHeader('Cookie', `.ROBLOSECURITY=_|WARNING:-DO-NOT-SHARE-THIS.--Sharing-this-will-allow-someone-to-log-in-as-you-and-to-steal-your-ROBUX-and-items.|${cookie}`);
  }
  proxyReq.removeHeader('roblox-id');
}

httpsProxy.on('error', onProxyError);
httpsProxy.on('proxyReq', onProxyReq);
httpProxy.on('error', onProxyError);
httpProxy.on('proxyReq', onProxyReq);

const app = express();

app.use('/proxy', express.static('./static'));
app.use('/proxy', api);

// Middleware to check the secret key
app.use((req, res, next) => {
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
      const token = authHeader.split(' ')[1];
      if (token === SECRET_KEY) {
          return next();
      }
  }
  res.status(401).send('🦑');
});

app.use(function (req, res, next) {
  if (blocked.includes(req.url) || reBlocked.some(pattern => req.url.match(pattern))) {
    return res.end('URL blocked.');
  }
  next();
});

app.use(function (req, res, next) {
  console.log('PROXY REQUEST; HOST: ' + req.headers.host + '; URL: ' + req.url + '; OPT: ' + req.body + '; COOKIE: ' + req.headers.cookie + ';');
  const subdomain = getSubdomain(req, true);
  const proto = subdomain === 'wiki.' ? 'http' : 'https';
  const target = `${proto}://${subdomain || 'www.'}roblox.com`;

  console.log(`Proxying to: ${target}`);
  const options = { target };

  if (proto === 'https') {
    httpsProxy.web(req, res, options);
  } else {
    httpProxy.web(req, res, options);
  }
});

app.use(function (err, req, res, next) {
  console.error(err);

  res.writeHead(500, {
    'Content-Type': 'text/plain'
  });

  res.end('Proxy handler failed.');
});

// HTTP Server
app.listen(PORT, function () {
  console.log(`Listening on ${DOMAIN}:${PORT}`);
});

// HTTPS Server
const credentials = {
  key: fs.readFileSync(`/etc/letsencrypt/live/${DOMAIN}/privkey.pem`, 'utf8'),
  cert: fs.readFileSync(`/etc/letsencrypt/live/${DOMAIN}/fullchain.pem`, 'utf8')
};

https.createServer(credentials, app).listen(HTTPS_PORT, () => {
  console.log(`Secure Express proxy running at https://${DOMAIN}:${HTTPS_PORT}`);
});
