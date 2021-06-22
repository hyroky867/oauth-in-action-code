import express, { Response, Request } from 'express';
import bodyParser from 'body-parser';
import cons from 'consolidate';
import __ from 'underscore';
import __s from 'underscore.string';
import randomstring from 'randomstring';
import querystring from 'querystring';
import mysql from 'mysql2';

import {
  AuthorizeRequest,
  Client,
  Code,
  AuthorizeParsedQs,
  ApproveRequest,
} from './types/Authorization';

const app = express();

app.use(bodyParser.json());
app.use(
  bodyParser.urlencoded({
    extended: true,
  }),
);

app.engine('html', cons.underscore);
app.set('view engine', 'html');
app.set('views', 'files/authorizationServer');
app.set('json spaces', 4);

const authServer = {
  authorizationEndpoint: 'http://0.0.0.0:9001/authorize',
  tokenEndpoint: 'http://0.0.0.0:9001/token',
};

// client information
const clients = [
  {
    clientId: 'oauth-client-1',
    clientSecret: 'oauth-client-secret-1',
    redirectUris: ['http://0.0.0.0:9000/callback'],
    scope: 'foo bar',
  },
];

const codes: {
  [key: string]: Code;
} = {};

const requests: {
  [key: string]: AuthorizeParsedQs;
} = {};

const getClient = (clientId: string) =>
  __.find(clients, (client: Client) => client.clientId === clientId);

app.get('/', (_: Request, res: Response): void =>
  res.render('index', {
    clients,
    authServer,
  }),
);

app.get('/authorize', (req: AuthorizeRequest, res: Response): void => {
  const client = getClient(req.query.clientId);

  if (client === undefined) {
    return res.render('error', {
      error: 'Unknown client',
    });
  }
  if (!__.contains(client.redirectUris, req.query.redirectUri)) {
    return res.render('error', {
      error: 'Invalid redirect URI',
    });
  }
  const rscope = req.query.scope ? req.query.scope.split(' ') : 'undefined';
  const cscope = client.scope ? client.scope.split(' ') : 'undefined';
  if (__.difference(rscope, cscope).length > 0) {
    // client asked for a scope it couldn't have
    const url = new URL(req.query.redirectUri);
    url.searchParams.append('error', 'invalid_scope');
    return res.redirect(url.toString());
  }

  const reqid = randomstring.generate(8);

  requests[reqid] = req.query;

  return res.render('approve', {
    client,
    reqid,
    scope: rscope,
  });
});

app.post('/approve', (req: ApproveRequest, res: Response) => {
  const { reqid } = req.body;
  const query = requests[reqid];
  delete requests[reqid];

  if (query === undefined) {
    return res.render('error', {
      error: 'No matching authorization request',
    });
  }

  const url = new URL(query.redirectUri);
  if (req.body.approve !== undefined) {
    if (query.responseType === 'code') {
      // user approved access
      const code = randomstring.generate(8);

      const { user } = req.body;

      const scope = __.filter(__.keys(req.body), (s) => __s.startsWith(s, 'scope_')).map((s) =>
        s.slice('scope_'.length),
      );
      const client = getClient(query.clientId);
      if (client === undefined) {
        return res.render('error', {
          error: 'No matching authorization request',
        });
      }
      const cscope = client.scope ? client.scope.split(' ') : '';
      if (__.difference(scope, cscope).length > 0) {
        // client asked for a scope it couldn't have
        url.searchParams.append('error', 'invalid_scope');

        return res.redirect(url.toString());
      }

      // save the code and request for later
      codes[code] = {
        authorizationEndpointRequest: query,
        scope,
        user,
      };

      url.searchParams.append('code', code);
      if (query.state !== undefined) {
        url.searchParams.append('state', query.state);
      }
      return res.redirect(url.toString());
    }
    // we got a response type we don't understand
    url.searchParams.append('error', 'unsupported_response_type');
    return res.redirect(url.toString());
  }
  // user denied access
  url.searchParams.append('error', 'access_denied');
  return res.redirect(url.toString());
});

app.post('/token', (req: Request, res: Response) => {
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
  if (req.body.clientId !== undefined) {
    if (clientId !== undefined) {
      return res.status(401).json({
        error: 'invalid_client',
      });
    }

    clientId = req.body.clientId;
    clientSecret = req.body.clientSecret;
  }

  const client = getClient(clientId);
  if (client === undefined) {
    return res.status(401).json({
      error: 'invalidClient',
    });
  }

  if (client.clientSecret !== clientSecret) {
    return res.status(401).json({
      error: 'invalidClient',
    });
  }

  if (req.body.grantType === 'authorizationCode') {
    const code = codes[req.body.code];

    if (code !== undefined) {
      delete codes[req.body.code]; // burn our code, it's been used
      if (code.authorizationEndpointRequest.clientId === clientId) {
        const accessToken = randomstring.generate();

        let cscope = null;
        if (code.scope !== undefined) {
          cscope = code.scope.join(' ');
        }

        const connection = mysql.createConnection({
          host: '0.0.0.0',
          user: 'developer',
          database: 'oAuth',
          port: 3306,
          password: 'root',
        });

        const query =
          'INSERT INTO `secrets` (`access_token`, `client_id`, `scope`) VALUES (?, ?, ?)';
        connection.execute(query, [accessToken, clientId, cscope]);

        const tokenResponse = {
          accessToken,
          tokenType: 'Bearer',
          scope: cscope,
        };

        return res.status(200).json(tokenResponse);
      }
      return res.status(400).json({
        error: 'invalid_grant',
      });
    }
    return res.status(400).json({
      error: 'invalid_grant',
    });
  }
  return res.status(400).json({
    error: 'unsupported_grant_type',
  });
});

app.use('/', express.static('files/authorizationServer'));

// clear the database on startup

const port = 9001;

const address = '0.0.0.0';

app.listen(port, address, () => {
  console.log('OAuth Authorization Server is listening at http://%s:%s', address, port);
});
