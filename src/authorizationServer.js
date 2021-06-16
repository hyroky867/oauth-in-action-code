import express from 'express';
import bodyParser from 'body-parser';
import cons from 'consolidate';
import _ from 'underscore';
import _s from 'underscore.string';
import randomstring from 'randomstring';
import nosql from 'nosql';
import url from 'url';
import querystring from 'querystring';

const app = express();

app.use(bodyParser.json());
app.use(
  bodyParser.urlencoded({
    extended: true,
  }),
); // support form-encoded bodies (for the token endpoint)

app.engine('html', cons.underscore);
app.set('view engine', 'html');
app.set('views', 'files/authorizationServer');
app.set('json spaces', 4);

// authorization server information
const authServer = {
  authorizationEndpoint: 'http://localhost:9001/authorize',
  tokenEndpoint: 'http://localhost:9001/token',
};

// client information
const clients = [
  {
    client_id: 'oauth-client-1',
    client_secret: 'oauth-client-secret-1',
    redirect_uris: ['http://localhost:9000/callback'],
    scope: 'foo bar',
  },
];

const codes = {};

const requests = {};

const getClient = (clientId) => _.find(clients, (client) => client.client_id === clientId);

app.get('/', (__, res) => {
  res.render('index', {
    clients,
    authServer,
  });
});

app.get('/authorize', (req, res) => {
  const client = getClient(req.query.client_id);

  if (!client) {
    console.log('Unknown client %s', req.query.client_id);
    res.render('error', {
      error: 'Unknown client',
    });
  } else if (!_.contains(client.redirect_uris, req.query.redirect_uri)) {
    console.log(
      'Mismatched redirect URI, expected %s got %s',
      client.redirect_uris,
      req.query.redirect_uri,
    );
    res.render('error', { error: 'Invalid redirect URI' });
  } else {
    const rscope = req.query.scope ? req.query.scope.split(' ') : undefined;
    const cscope = client.scope ? client.scope.split(' ') : undefined;
    if (_.difference(rscope, cscope).length > 0) {
      // client asked for a scope it couldn't have
      const urlParsed = url.parse(req.query.redirect_uri);
      delete urlParsed.search; // this is a weird behavior of the URL library
      urlParsed.query = urlParsed.query || {};
      urlParsed.query.error = 'invalid_scope';
      res.redirect(url.format(urlParsed));
      return;
    }

    const reqid = randomstring.generate(8);

    requests[reqid] = req.query;

    res.render('approve', {
      client,
      reqid,
      scope: rscope,
    });
  }
});

app.post('/approve', (req, res) => {
  const { reqid } = req.body;
  const query = requests[reqid];
  delete requests[reqid];

  if (!query) {
    // there was no matching saved request, this is an error
    res.render('error', { error: 'No matching authorization request' });
    return;
  }

  if (req.body.approve) {
    if (query.response_type === 'code') {
      // user approved access
      const code = randomstring.generate(8);

      const { user } = req.body;

      const scope = _.filter(_.keys(req.body), (s) => _s.startsWith(s, 'scope_')).map((s) =>
        s.slice('scope_'.length),
      );
      const client = getClient(query.client_id);
      const cscope = client.scope ? client.scope.split(' ') : undefined;
      if (_.difference(scope, cscope).length > 0) {
        // client asked for a scope it couldn't have
        const urlParsed = url.parse(query.redirect_uri);
        delete urlParsed.search; // this is a weird behavior of the URL library
        urlParsed.query = urlParsed.query || {};
        urlParsed.query.error = 'invalid_scope';
        res.redirect(url.format(urlParsed));
        return;
      }

      // save the code and request for later
      codes[code] = { authorizationEndpointRequest: query, scope, user };

      const urlParsed = url.parse(query.redirect_uri);
      delete urlParsed.search; // this is a weird behavior of the URL library
      urlParsed.query = urlParsed.query || {};
      urlParsed.query.code = code;
      urlParsed.query.state = query.state;
      res.redirect(url.format(urlParsed));
    } else {
      // we got a response type we don't understand
      const urlParsed = url.parse(query.redirect_uri);
      delete urlParsed.search; // this is a weird behavior of the URL library
      urlParsed.query = urlParsed.query || {};
      urlParsed.query.error = 'unsupported_response_type';
      res.redirect(url.format(urlParsed));
    }
  } else {
    // user denied access
    const urlParsed = url.parse(query.redirect_uri);
    delete urlParsed.search; // this is a weird behavior of the URL library
    urlParsed.query = urlParsed.query || {};
    urlParsed.query.error = 'access_denied';
    res.redirect(url.format(urlParsed));
  }
});

app.post('/token', (req, res) => {
  const auth = req.headers.authorization;
  let clientId = '';
  let clientSecret = '';
  if (auth) {
    // check the auth header
    const clientCredentials = Buffer.from(auth.slice('basic '.length), 'base64')
      .toString()
      .split(':');

    clientId = querystring.unescape(clientCredentials[0]);
    clientSecret = querystring.unescape(clientCredentials[1]);
  }

  // otherwise, check the post body
  if (req.body.client_id) {
    if (clientId) {
      // if we've already seen the client's credentials in the authorization header, this is an error
      console.log('Client attempted to authenticate with multiple methods');
      res.status(401).json({ error: 'invalid_client' });
      return;
    }

    clientId = req.body.client_id;
    clientSecret = req.body.client_secret;
  }

  const client = getClient(clientId);
  if (!client) {
    console.log('Unknown client %s', clientId);
    res.status(401).json({ error: 'invalid_client' });
    return;
  }

  if (client.client_secret !== clientSecret) {
    console.log('Mismatched client secret, expected %s got %s', client.client_secret, clientSecret);
    res.status(401).json({ error: 'invalid_client' });
    return;
  }

  if (req.body.grant_type === 'authorization_code') {
    const code = codes[req.body.code];

    if (code) {
      delete codes[req.body.code]; // burn our code, it's been used
      if (code.authorizationEndpointRequest.client_id === clientId) {
        const accessToken = randomstring.generate();

        let cscope = null;
        if (code.scope) {
          cscope = code.scope.join(' ');
        }

        nosql.insert({
          access_token: accessToken,
          client_id: clientId,
          scope: cscope,
        });

        console.log('Issuing access token %s', accessToken);
        console.log('with scope %s', cscope);

        const tokenResponse = {
          access_token: accessToken,
          token_type: 'Bearer',
          scope: cscope,
        };

        res.status(200).json(tokenResponse);
        console.log('Issued tokens for code %s', req.body.code);
      } else {
        console.log(
          'Client mismatch, expected %s got %s',
          code.authorizationEndpointRequest.client_id,
          clientId,
        );
        res.status(400).json({ error: 'invalid_grant' });
      }
    } else {
      console.log('Unknown code, %s', req.body.code);
      res.status(400).json({ error: 'invalid_grant' });
    }
  } else {
    console.log('Unknown grant type %s', req.body.grant_type);
    res.status(400).json({ error: 'unsupported_grant_type' });
  }
});

app.use('/', express.static('files/authorizationServer'));

// clear the database on startup

const server = app.listen(9001, 'localhost', () => {
  const { port, address } = server.address();

  console.log('OAuth Authorization Server is listening at http://%s:%s', address, port);
});
