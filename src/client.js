import express, { request } from 'express';
import cons from 'consolidate';
import __ from 'underscore';
import url from 'url';
import querystring from 'querystring';
import qs from 'qs';
import randomstring from 'randomstring';

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
  client_id: 'oauth-client-1',
  client_secret: 'oauth-client-secret-1',
  redirect_uris: ['http://localhost:9000/callback'],
};

const protectedResource = 'http://localhost:9002/resource';

let state = null;
let accessToken = null;
const scope = null;

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
    access_token: accessToken,
    scope,
  });
});

app.get('/authorize', (_, res) => {
  state = randomstring.generate();
  const authorizeUrl = buildUrl(authServer.authorizationEndpoint, {
    response_type: 'code',
    client_id: client.client_id,
    redirect_uri: client.redirect_uris[0],
    state,
  });

  console.log('redirect', authorizeUrl);
  res.redirect(authorizeUrl);
});

app.get('/callback', (req, res) => {
  const { code } = req.query;

  const formData = qs.stringify({
    grant_type: 'authorization_code',
    code,
    redirect_uri: client.redirect_uris[0],
  });

  const headers = {
    'Content-Type': 'application/x-www-form-urlencoded',
    Authorization: `Basic ${encodeClientCredentials(client.client_id, client.client_secret)}`,
  };

  const tokRes = request('post', authServer.tokenEndpoint, {
    body: formData,
    headers,
  });

  const body = JSON.parse(tokRes.getBody());

  accessToken = body.access_token;

  res.render('index', {
    access_token: body.access_token,
    scope,
  });
});

app.get('/fetch_resource', (req, res) => {
  /*
   * Use the access token to call the resource server
   */
});

app.use('/', express.static('files/client'));

const server = app.listen(9000, 'localhost', () => {
  const { port, address } = server.address();
  console.log('OAuth Client is listening at http://%s:%s', address, port);
});
