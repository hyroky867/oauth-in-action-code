import express from 'express';
import cons from 'consolidate';
import __ from 'underscore';
import url from 'url';
import querystring from 'querystring';
import qs from 'qs';
import randomstring from 'randomstring';
import syncRequest from 'sync-request';

const app = express();

app.engine('html', cons.underscore);
app.set('view engine', 'html');
app.set('views', 'files/client');

// authorization server information
const authServer = {
  authorizationEndpoint: 'http://localhost:9001/authorize',
  tokenEndpoint: 'http://localhost:9001/token',
};

// client information

/*
 * Add the client information in here
 */
const client = {
  clientId: 'oauth-client-1',
  clientSecret: 'oauth-client-secret-1',
  redirectUris: ['http://localhost:9000/callback'],
  scope: 'foo',
};

const protectedResource = 'http://localhost:9002/resource';

let state = null;

let accessToken = '987tghjkiu6trfghjuytrghj';
let scope = null;
const refreshToken = 'j2r3oj32r23rmasd98uhjrk2o3i';

const buildUrl = (base, options, hash) => {
  const newUrl = url.parse(base, true);
  delete newUrl.search;
  if (!newUrl.query) {
    newUrl.query = {};
  }
  __.each(options, (value, key) => {
    newUrl.query[key] = value;
  });
  if (hash) {
    newUrl.hash = hash;
  }

  return url.format(newUrl);
};

const encodeClientCredentials = (clientId, clientSecret) =>
  Buffer.from(`${querystring.escape(clientId)}:${querystring.escape(clientSecret)}`).toString(
    'base64',
  );

app.get('/', (_, res) => {
  res.render('index', {
    accessToken,
    scope,
    refreshToken,
  });
});

app.get('/authorize', (_, res) => {
  accessToken = null;
  scope = null;
  state = randomstring();

  const authorizeUrl = buildUrl(authServer.authorizationEndpoint, {
    responseType: 'code',
    scope: client.scope,
    clientId: client.clientId,
    redirectUri: client.redirectUris[0],
    state,
  });

  console.log('redirect', authorizeUrl);
  res.redirect(authorizeUrl);
});

app.get('/callback', (req, res) => {
  if (req.query.error) {
    // it's an error response, act accordingly
    res.render('error', { error: req.query.error });
    return;
  }

  if (req.query.state !== state) {
    res.render('error', {
      error: 'State value did not match',
    });
    return;
  }

  const { code } = req.query;

  const formData = qs.stringify({
    grantType: 'authorization_code',
    code,
    redirectUri: client.redirectUris[0],
  });

  const headers = {
    'Content-Type': 'application/x-www-form-urlencoded',
    Authorization: `Basic ${encodeClientCredentials(client.clientId, client.clientSecret)}`,
  };

  const tokRes = syncRequest('post', authServer.tokenEndpoint, {
    body: formData,
    headers,
  });

  const body = JSON.parse(tokRes.getBody());

  console.log(body);

  accessToken = body.accessToken;

  res.render('index', {
    accessToken,
    scope,
  });
});

app.get('/fetch_resource', (req, res) => {
  if (accessToken) {
    res.render('error', {
      error: 'Missing access token.',
    });
  }

  const headers = {
    Authorization: `Beaser ${accessToken}`,
  };

  const resource = syncRequest('POST', protectedResource, {
    headers,
  });

  const { statusCode } = resource;

  if (statusCode >= 200 && statusCode < 300) {
    const body = JSON.parse(resource.getBody());
    res.render('data', {
      resource: body,
    });
  }
  res.render('error', {
    error: `Server returned response code: ${statusCode}`,
  });
});

app.use('/', express.static('files/client'));

const server = app.listen(9000, 'localhost', () => {
  const { port, address } = server.address();
  console.log('OAuth Client is listening at http://%s:%s', address, port);
});
