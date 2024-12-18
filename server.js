const express = require('express');
const fs = require('fs');
const https = require('https');
const proxy = require('http-proxy');
const url = require('url');

const api = require('./api.js');
const blocked = require('./static/blocked.json');
const reBlocked = require('./static/re_blocked.json');
const allowedSubdomains = require('./static/allowed_subdomains.json');

const DOMAIN = process.env.DOMAIN || "localhost";
const HTTP_PORT = process.env.HTTP_PORT || 80;
const HTTPS_PORT = process.env.HTTPS_PORT || 443;
const SECRET_KEY = process.env.SECRET_KEY;
const SUBDOMAIN_AS_PATH = true;
const HOST_HTTPS_SERVER = true;

const RESPONSE_INVALID_AUTHENTICATION = '🦑';
const RESPONSE_INVALID_URL = 'URL blocked.';
const RESPONSE_INVALID_SUBDOMAIN = 'Subdomain not allowed.';

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
  proxyReq.setHeader('User-Agent', 'Roblox/Darwin RobloxApp/0.0.0.0 (GlobalDist; RobloxDirectDownload)');
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
  res.status(401).send(RESPONSE_INVALID_AUTHENTICATION);
});

app.use(function (req, res, next) {
  if (blocked.includes(req.url) || reBlocked.some(pattern => req.url.match(pattern))) {
    return res.end(RESPONSE_INVALID_URL);
  }
  next();
});

app.use(function (req, res, next) {
  let subdomain = getSubdomain(req, false);
  subdomain = subdomain.replace(/\.$/, '');
  if (!allowedSubdomains.includes(subdomain)) {
    return res.end(RESPONSE_INVALID_SUBDOMAIN);
  }
  next();
});

app.use(function (req, res, next) {
  console.log(`PROXY REQUEST; HOST: ${req.headers.host}; URL: ${req.url};`);

  const subdomain = getSubdomain(req, true);
  const proto = req.protocol;
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
app.listen(HTTP_PORT, function () {
  console.log(`Listening on ${DOMAIN}:${HTTP_PORT}`);
});

// HTTPS Server
if (HOST_HTTPS_SERVER) {
  const credentials = {
    key: fs.readFileSync(`/etc/letsencrypt/live/${DOMAIN}/privkey.pem`, 'utf8'),
    cert: fs.readFileSync(`/etc/letsencrypt/live/${DOMAIN}/fullchain.pem`, 'utf8')
  };

  https.createServer(credentials, app).listen(HTTPS_PORT, () => {
    console.log(`Secure Express proxy running at https://${DOMAIN}:${HTTPS_PORT}`);
  });
}
