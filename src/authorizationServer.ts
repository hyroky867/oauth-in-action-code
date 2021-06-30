import express, { Response, Request } from 'express';
import cons from 'consolidate';
import __ from 'underscore';
import __s from 'underscore.string';
import randomstring from 'randomstring';
import querystring from 'querystring';
import mysql, { RowDataPacket } from 'mysql2/promise';
import {
  AuthServer,
  AuthorizeRequest,
  Client,
  Code,
  AuthorizeParsedQs,
  ApproveRequest,
  User,
  TokenRequest,
  TokenResponse,
  RefreshToken,
  AccessToken,
} from './types/Authorization';

const app = express();

app.use(express.json());
app.use(
  express.urlencoded({
    extended: true,
  }),
);

app.engine('html', cons.underscore);
app.set('view engine', 'html');
app.set('views', 'files/authorizationServer');
app.set('json spaces', 4);

const authServer: AuthServer = {
  authorizationEndpoint: 'http://0.0.0.0:9001/authorize',
  tokenEndpoint: 'http://0.0.0.0:9001/token',
};

// client information
const clients: Client[] = [
  {
    clientId: 'oauth-client-1',
    clientSecret: 'oauth-client-secret-1',
    redirectUris: ['http://0.0.0.0:9000/callback'],
    scope: '',
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

const userInfo: {
  [key: string]: User;
} = {
  alice: {
    sub: '9XE3-JI34-00132A',
    preferredUsername: 'alice',
    name: 'Alice',
    email: 'alice.wonderland@example.com',
    emailVerified: true,
  },
  bob: {
    sub: '1ZT5-OE63-57383B',
    preferredUsername: 'bob',
    name: 'Bob',
    email: 'bob.loblob@example.net',
    emailVerified: false,
  },
  carol: {
    sub: 'F5Q1-L6LGG-959FS',
    preferredUsername: 'carol',
    name: 'Carol',
    email: 'carol.lewis@example.net',
    emailVerified: true,
    userName: 'clewis',
    password: 'user password!',
  },
};

const getUser = (userName: string) => __.find(userInfo, (user: User) => user.userName === userName);

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
  const rscope = req.query.scope ? req.query.scope.split(' ') : '';
  const cscope = client.scope ? client.scope.split(' ') : '';
  if (__.difference(rscope, cscope).length > 0) {
    // client asked for a scope it couldn't have
    const url = new URL(req.query.redirectUri);
    url.searchParams.append('error', 'invalidScope');
    console.log('/authorize 1: %s', url.toString());
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

const generateTokens = async (
  clientId: string,
  user: User,
  scope: string[],
  generateRefreshToken = false,
): Promise<TokenResponse> => {
  const accessToken: AccessToken = randomstring.generate();

  let refreshToken: RefreshToken = null;

  if (generateRefreshToken) {
    refreshToken = randomstring.generate();
  }

  const connection = await mysql.createConnection({
    host: 'db',
    user: 'developer',
    database: 'oAuth',
    port: 3306,
    password: 'root',
  });

  const insertAccessToken = refreshToken ?? accessToken;

  const query =
    'INSERT INTO `secrets` (`access_token`, `client_id`, `scope`, `user`) VALUES (?, ?, ?, ?)';
  await connection.execute(query, [insertAccessToken, clientId, scope, JSON.stringify(user)]);
  await connection.end();

  return {
    accessToken,
    tokenType: 'Bearer',
    refreshToken,
    scope: scope === undefined ? null : scope.join(' '),
  };
};

app.post('/approve', (req: ApproveRequest, res: Response): void => {
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

      const code = randomstring.generate(8);
      // save the code and request for later
      codes[code] = {
        authorizationEndpointRequest: query,
        scope,
        user: req.body.user,
      };

      url.searchParams.append('code', code);
      if (query.state !== undefined) {
        url.searchParams.append('state', query.state);
      }
      return res.redirect(url.toString());
    }
    if (query.responseType === 'token') {
      const { user } = req.body;

      const scope = __.filter(__.keys(req.body), (s) => __.string.startsWith(s, 'scope_')).map(
        (s) => s.slice('scope_'.length),
      );
      const client = getClient(query.clientId);
      if (client === undefined) {
        return res.render('error', {
          error: 'No matching authorization request',
        });
      }
      const cscope = client.scope ? client.scope.split(' ') : [];
      if (__.difference(scope, cscope).length > 0) {
        // client asked for a scope it couldn't have
        url.searchParams.append('error', 'invalid_scope');

        return res.redirect(url.toString());
      }

      const existsUser = userInfo[user];
      if (existsUser === undefined) {
        console.log('Unknown user %s', user);
        return res.status(500).render('error', {
          error: `Unknown user ${user}`,
        });
      }

      console.log('User %j', existsUser);

      const tokenResponse = generateTokens(query.clientId, existsUser, cscope);

      let hash = tokenResponse;
      if (query.state !== undefined) {
        const stateObj = {
          state: query.state,
        };
        hash = {
          ...stateObj,
          ...tokenResponse,
        };
      }

      url.searchParams.append('hash', JSON.stringify(hash));
      return res.redirect(url.toString());
    }
    url.searchParams.append('error', 'unsupportedResponseType');
    return res.redirect(url.toString());
  }
  // user denied access
  url.searchParams.append('error', 'accessDenied');
  return res.redirect(url.toString());
});

app.post('/token', async (req: TokenRequest, res: Response): Promise<void> => {
  const auth = req.headers.authorization;
  let clientId = '';
  let clientSecret = '';
  if (auth !== undefined) {
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
      res.status(401).json({
        error: 'invalidClient',
      });
      return;
    }

    clientId = req.body.clientId;
    clientSecret = req.body.clientSecret;
  }

  const client = getClient(clientId);
  if (client === undefined) {
    res.status(401).json({
      error: 'invalidClient',
    });
    return;
  }

  if (client.clientSecret !== clientSecret) {
    console.log('/token %s', clientSecret);
    res.status(401).json({
      error: 'invalidClient',
    });
    return;
  }
  console.log('/token %s', JSON.stringify(req.body));

  if (req.body.grantType === 'authorizationCode') {
    const code = codes[req.body.code];

    if (code !== undefined) {
      delete codes[req.body.code]; // burn our code, it's been used
      if (code.authorizationEndpointRequest.client_id === clientId) {
        const user = userInfo[code.user];
        const tokenResponse = generateTokens(clientId, user, code.scope, true);
        res.status(200).json(tokenResponse);
        return;
      }
      res.status(400).json({
        error: 'invalid_grant',
      });
      return;
    }
    res.status(400).json({
      error: 'invalid_grant',
    });
    return;
  }
  if (req.body.grantType === 'clientCredentials') {
    const scope = req.body.scope ? req.body.scope.split(' ') : [];
    const cscope = client.scope ? client.scope.split(' ') : [];
    if (__.difference(scope, cscope).length > 0) {
      // client asked for a scope it couldn't have
      res.status(400).json({
        error: 'invalid_scope',
      });
      return;
    }

    const accessToken = randomstring.generate();

    const connection = await mysql.createConnection({
      host: 'db',
      user: 'developer',
      database: 'oAuth',
      port: 3306,
      password: 'root',
    });

    const query = 'INSERT INTO `secrets` (`access_token`, `client_id`, `scope`) VALUES (?, ?, ?)';
    await connection.execute(query, [accessToken, clientId, cscope]);
    await connection.end();

    res.status(200).json({
      accessToken,
      tokenType: 'Bearer',
      scope: scope.join(' '),
    });
  } else if (req.body.grantType === 'refreshToken') {
    const connection = await mysql.createConnection({
      host: 'db',
      user: 'developer',
      database: 'oAuth',
      port: 3306,
      password: 'root',
    });
    const sql = 'SELECT * FROM `secrets` WHERE `access_token` = ?';
    const [rows] = await connection.execute<RowDataPacket[]>(sql, [req.body.refreshToken]);
    if (rows.length !== 1) {
      res.status(401).end();
      await connection.end();
      return;
    }
    if (rows[0].client_id !== clientId) {
      res.status(400).end();
      await connection.end();
      return;
    }
    const newAccessToken = randomstring.generate();

    const query = 'INSERT INTO `secrets` (`access_token`, `client_id`, `scope`) VALUES (?, ?, ?)';
    await connection.execute(query, [newAccessToken, clientId, '']);
    await connection.end();

    const tokenResponse: TokenResponse = {
      accessToken: newAccessToken,
      tokenType: 'Bearer',
      refreshToken: req.body.refreshToken,
      scope: null,
    };
    res.status(200).json(tokenResponse);
  } else if (req.body.grantType === 'password') {
    const user = getUser(req.body.userName);
    if (user === undefined) {
      res.status(401).json({
        error: 'invalid_grant',
      });
      return;
    }

    if (user.password !== req.body.password) {
      res.status(401).json({
        error: 'invalid_grant',
      });
      return;
    }

    res.status(200).json(generateTokens(clientId, user, [req.body.scope]));
  } else {
    res.status(400).json({
      error: 'unsupported_grant_type',
    });
  }
});

app.use('/', express.static('files/authorizationServer'));

// clear the database on startup

const port = 9001;

const address = '0.0.0.0';

app.listen(port, address, () => {
  console.log('OAuth Authorization Server is listening at http://%s:%s', address, port);
});
