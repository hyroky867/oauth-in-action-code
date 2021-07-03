import express, { Response, Request } from 'express';
import cons from 'consolidate';
import randomstring from 'randomstring';
import querystring from 'querystring';
import mysql, { RowDataPacket } from 'mysql2/promise';
import {
  ApproveRequestBody,
  ClientCredential,
  AuthServer,
  AuthorizeRequest,
  Client,
  Code,
  AuthorizeParsedQs,
  ApproveRequest,
  TokenRequest,
  TokenResponse,
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
    scope: 'foo bar',
  },
];

const codes: {
  [key: string]: Code;
} = {};

const requests: {
  [key: string]: AuthorizeParsedQs;
} = {};

const getClient = (clientId: string): Client | undefined =>
  clients.find((client) => client.clientId === clientId) ?? undefined;

interface BuildUrlParams {
  base: string;
  options: {
    [key: string]: string;
  };
  hash?: string;
}

const buildUrl = ({ base, options, hash }: BuildUrlParams): string => {
  const newUrl = new URL(base);
  Object.keys(options).forEach((key: string) => {
    newUrl.searchParams.append(key, options[key]);
  });
  if (hash !== undefined) {
    newUrl.searchParams.append('hash', hash);
  }
  return newUrl.toString();
};

const decodeClientCredentials = (auth: string): ClientCredential => {
  const clientCredentials = Buffer.from(auth.slice('basic '.length), 'base64')
    .toString()
    .split(':');
  return {
    id: querystring.unescape(clientCredentials[0]),
    secret: querystring.unescape(clientCredentials[1]),
  };
};

const getScopesFromForm = (body: ApproveRequestBody): string[] =>
  Object.keys(body)
    .filter((key: string) => key.startsWith('scope_'))
    .map((key: string) => key.slice('scope_'.length));

app.get('/', (_: Request, res: Response): void =>
  res.render('index', {
    clients,
    authServer,
  }),
);

app.get('/authorize', (req: AuthorizeRequest, res: Response): void => {
  const client = getClient(req.query.clientId);

  if (client === undefined) {
    console.log('Unknown client %s', req.query.clientId);

    return res.render('error', {
      error: 'Unknown client',
    });
  }
  if (client.redirectUris.includes(req.query.redirectUri) === false) {
    console.log(
      'Mismatched redirect URI, expected %s got %s',
      client.redirectUris,
      req.query.redirectUri,
    );

    return res.render('error', {
      error: 'Invalid redirect URI',
    });
  }

  const rscope = req.query.scope ? req.query.scope.split(' ') : [];
  const cscope = client.scope ? client.scope.split(' ') : [];
  // if (rscope !== cscope) {
  const isSame = rscope.forEach((rscopeItem: string) => {
    cscope.forEach((cscopeItem: string) => {
      const result = rscopeItem === cscopeItem;
      if (result === false) {
        return false;
      }
    });
  });
  if (r) {
    return res.redirect(
      buildUrl({
        base: req.query.redirectUri,
        options: {
          error: 'invalidScope',
        },
      }),
    );
  }

  const reqid = randomstring.generate(8);

  requests[reqid] = req.query;

  return res.render('approve', {
    client,
    reqid,
    scope: rscope,
  });
});

app.post('/approve', (req: ApproveRequest, res: Response): void => {
  const { reqid } = req.body;
  const query = requests[reqid];
  delete requests[reqid];

  if (query === undefined) {
    return res.render('error', {
      error: 'No matching authorization request',
    });
  }

  if (req.body.approve !== undefined) {
    if (query.responseType === 'code') {
      const rscope = getScopesFromForm(req.body);
      const client = getClient(query.clientId);
      if (client === undefined) {
        return res.render('error', {
          error: `client notfound clientId:  ${query.clientId}`,
        });
      }
      const cscope = client.scope ? client.scope.split(' ') : '';
      if ((rscope.length, cscope.length)) {
        return res.redirect(
          buildUrl({
            base: query.redirectUri,
            options: {
              error: 'invalidScope',
            },
          }),
        );
      }

      const code = randomstring.generate(8);

      codes[code] = {
        request: query,
      };
      return res.redirect(
        buildUrl({
          base: query.redirectUri,
          options: {
            code,
            state: query.state ?? '',
          },
        }),
      );
    }
    return res.redirect(
      buildUrl({
        base: query.redirectUri,
        options: {
          error: 'unsupportedResponseType',
        },
      }),
    );
  }
  // user denied access
  return res.redirect(
    buildUrl({
      base: query.redirectUri,
      options: {
        error: 'accessDenied',
      },
    }),
  );
});

app.post('/token', async (req: TokenRequest, res: Response): Promise<void> => {
  const auth = req.headers.authorization;
  let clientId = '';
  let clientSecret = '';
  let clientCredentials = null;
  if (auth !== undefined) {
    // check the auth header
    clientCredentials = decodeClientCredentials(auth);
    clientId = clientCredentials.id;
    clientSecret = clientCredentials.secret;
  }

  // otherwise, check the post body
  if (req.body.clientId !== undefined) {
    if (clientId !== undefined) {
      console.log('Client attempted to authenticate with multiple methods');

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
    console.log('Unknown client %s', clientId);
    res.status(401).json({
      error: 'invalidClient',
    });
    return;
  }

  if (client.clientSecret !== clientSecret) {
    console.log('Mismatched client secret, expected %s got %s', client.clientSecret, clientSecret);

    res.status(401).json({
      error: 'invalidClient',
    });
    return;
  }
  if (req.body.grantType === 'authorizationCode') {
    const code = codes[req.body.code];

    if (code !== undefined) {
      delete codes[req.body.code]; // burn our code, it's been used
      if (code.request.clientId === clientId) {
        const accessToken = randomstring.generate();
        const refreshToken = randomstring.generate();

        console.log('Issuing access token %s', accessToken);

        const connection = await mysql.createConnection({
          host: 'db',
          user: 'developer',
          database: 'oAuth',
          port: 3306,
          password: 'root',
        });

        const query =
          'INSERT INTO `secrets` (`access_token`, `refresh_token`, `client_id`, `scope`) VALUES (?, ?, ?, ?)';
        await connection.execute(query, [accessToken, refreshToken, clientId, '']);
        await connection.end();

        const tokenResponse: TokenResponse = {
          accessToken,
          tokenType: 'Bearer',
          refreshToken,
        };
        res.status(200).json(tokenResponse);
        console.log('Issued tokens for code %s', req.body.code);
        return;
      }
      console.log('Client mismatch, expected got %s', clientId);
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

  if (req.body.grantType === 'refreshToken') {
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
      const deleteQuery = 'DELETE FROM `secrets` WHERE `refresh_token` = ?';
      connection.execute(deleteQuery, [req.body.refreshToken]);
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

    const query =
      'INSERT INTO `secrets` (`access_token`, `client_id`, `refresh_token`, `scope`) VALUES (?, ?, ?, ?)';
    await connection.execute(query, [newAccessToken, clientId, '', '']);
    await connection.end();

    const tokenResponse: TokenResponse = {
      accessToken: newAccessToken,
      tokenType: 'Bearer',
      refreshToken: req.body.refreshToken,
      scope: null,
    };
    res.status(200).json(tokenResponse);
    return;
  }
  console.log('Unknown grant type %s', req.body.grantType);

  res.status(400).json({
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
