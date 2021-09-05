import express, { Response, Request } from 'express';
import cons from 'consolidate';
import randomstring from 'randomstring';
import querystring from 'querystring';
import mysql from 'mysql2/promise';
import jose from 'jsrsasign';
import {
  IDToken,
  TokenRequestHeader,
  User,
  RSAKey,
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
  AccessToken,
  RefreshToken,
  TokenRequestPayload,
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
    scope: 'greeting',
  },
  {
    clientId: 'oauth-client-2',
    clientSecret: 'oauth-client-secret-2',
    redirectUris: ['http://0.0.0.0:9000/callback'],
    scope: 'bar',
  },
  {
    clientId: 'native-client-1',
    clientSecret: 'native-client-secret-1',
    redirectUris: ['mynativeapp://'],
    scope: 'openid profile email phone address',
  },
];

const rsaKey: RSAKey = {
  alg: 'RS256',
  d: 'ZXFizvaQ0RzWRbMExStaS_-yVnjtSQ9YslYQF1kkuIoTwFuiEQ2OywBfuyXhTvVQxIiJqPNnUyZR6kXAhyj__wS_Px1EH8zv7BHVt1N5TjJGlubt1dhAFCZQmgz0D-PfmATdf6KLL4HIijGrE8iYOPYIPF_FL8ddaxx5rsziRRnkRMX_fIHxuSQVCe401hSS3QBZOgwVdWEb1JuODT7KUk7xPpMTw5RYCeUoCYTRQ_KO8_NQMURi3GLvbgQGQgk7fmDcug3MwutmWbpe58GoSCkmExUS0U-KEkHtFiC8L6fN2jXh1whPeRCa9eoIK8nsIY05gnLKxXTn5-aPQzSy6Q',
  e: 'AQAB',
  n: 'p8eP5gL1H_H9UNzCuQS-vNRVz3NWxZTHYk1tG9VpkfFjWNKG3MFTNZJ1l5g_COMm2_2i_YhQNH8MJ_nQ4exKMXrWJB4tyVZohovUxfw-eLgu1XQ8oYcVYW8ym6Um-BkqwwWL6CXZ70X81YyIMrnsGTyTV6M8gBPun8g2L8KbDbXR1lDfOOWiZ2ss1CRLrmNM-GRp3Gj-ECG7_3Nx9n_s5to2ZtwJ1GS1maGjrSZ9GRAYLrHhndrL_8ie_9DS2T-ML7QNQtNkg2RvLv4f0dpjRYI23djxVtAylYK4oiT_uEMgSkc4dxwKwGuBxSO0g9JOobgfy0--FUHHYtRi0dOFZw',
  kty: 'RSA',
  kid: 'authserver',
};

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
};

const codes: {
  [key: string]: Code;
} = {};

const requests: {
  [key: string]: AuthorizeParsedQs;
} = {};

const getClient = (clientId: string): Client | undefined =>
  clients.find((client) => client.clientId === clientId) ?? undefined;

const getUser = (userName: string): User => userInfo[userName];

interface BuildUrlParams {
  base: string;
  options?: {
    [key: string]: string;
  };
  hash?: string;
}

const buildUrl = ({ base, options, hash }: BuildUrlParams): string => {
  const newUrl = new URL(base);
  if (options !== undefined) {
    Object.keys(options).forEach((key: string) => {
      newUrl.searchParams.append(key, options[key]);
    });
  }
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

const hasDiffScope = (scope1: string[], scope2: string[]): boolean =>
  scope1.filter((scope1Item: string) => scope2.indexOf(scope1Item) === -1).length > 0;

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

  if (hasDiffScope(rscope, cscope)) {
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

const generateTokens = async (
  clientId: string,
  user: User,
  scope: string[],
  isGenerateRefreshToken = false,
): Promise<TokenResponse> => {
  const accessToken: AccessToken = randomstring.generate();

  let refreshToken: RefreshToken = null;

  if (isGenerateRefreshToken === true) {
    refreshToken = randomstring.generate();
  }

  const header: TokenRequestHeader = {
    typ: 'JWT',
    alg: 'RS256',
    kid: rsaKey.kid,
  };

  const iat = Math.floor(Date.now() / 1000);
  const payload: TokenRequestPayload = {
    iss: 'http://localhost:9001/',
    sub: user.sub,
    aud: clientId,
    iat,
    exp: iat + 5 * 60,
  };

  const privateKey = jose.KEYUTIL.getKey(rsaKey);
  const idToken: IDToken = jose.KJUR.jws.JWS.sign(
    'RSA256',
    JSON.stringify(header),
    JSON.stringify(payload),
    // @ts-ignore
    privateKey,
  );

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
    idToken,
  };
};

app.post('/approve', (req: ApproveRequest, res: Response): void => {
  const { reqid, user } = req.body;
  const query = requests[reqid];
  delete requests[reqid];

  if (query === undefined) {
    return res.render('error', {
      error: 'No matching authorization request',
    });
  }

  if (req.body.approve !== undefined) {
    const scope = Object.keys(req.body)
      .filter((s: string) => s.startsWith('scope_'))
      .map((s: string) => s.slice('scope_'.length));
    const client = getClient(query.clientId);
    if (client === undefined) {
      return res.render('error', {
        error: `client notfound clientId:  ${query.clientId}`,
      });
    }
    const cscope = client.scope ? client.scope.split(' ') : [];
    if (hasDiffScope(scope, cscope)) {
      return res.redirect(
        buildUrl({
          base: query.redirectUri,
          options: {
            error: 'invalidScope',
          },
        }),
      );
    }
    if (query.responseType === 'code') {
      const code = randomstring.generate(8);
      codes[code] = {
        request: query,
        scope,
        user: getUser(user),
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

    // if (query.responseType === 'token') {
    //   const savedUser = getUser(user);
    //   if (savedUser === undefined) {
    //     console.log(`Unknown user ${user}`);
    //     return res.status(500).render('error', {
    //       error: `Unknown user ${user}`,
    //     });
    //   }

    //   const tokenResponse = generateTokens(query.clientId, savedUser, cscope);
    //   const base = query.redirectUri;
    //   const hash = qs.stringify(tokenResponse);

    //   if (query.state === undefined) {
    //     return res.redirect(
    //       buildUrl({
    //         base,
    //         hash,
    //       }),
    //     );
    //   }
    //   const options = {
    //     state: query.state,
    //   };
    //   return res.redirect(
    //     buildUrl({
    //       base,
    //       options,
    //       hash,
    //     }),
    //   );
    // }

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
  const accessToken = randomstring.generate();

  console.log('Issuing access token %s', accessToken);

  const connection = await mysql.createConnection({
    host: 'db',
    user: 'developer',
    database: 'oAuth',
    port: 3306,
    password: 'root',
  });

  if (req.body.grantType === 'authorizationCode') {
    const code = codes[req.body.code];

    if (code !== undefined) {
      delete codes[req.body.code]; // burn our code, it's been used
      if (code.request.clientId === clientId) {
        const scope = code.scope === undefined ? null : code.scope.join(' ');

        const query =
          'INSERT INTO `secrets` (`access_token`, `refresh_token`, `client_id`, `scope`) VALUES (?, ?, ?, ?)';
        await connection.execute(query, [accessToken, '', clientId, scope]);
        await connection.end();

        let idToken;

        if (code.scope.includes('openid') && code.user?.sub !== undefined) {
          const header: TokenRequestHeader = {
            typ: 'JWT',
            alg: rsaKey.alg,
            kid: rsaKey.kid,
          };

          const iPayload: TokenRequestPayload = {
            iss: 'http://localhost:9001/',
            sub: code.user.sub,
            aud: client.clientId,
            iat: Math.floor(Date.now() / 1000),
            exp: Math.floor(Date.now() / 1000) + 5 * 60,
            nonce: code.request?.nonce,
          };

          const privateKey = jose.KEYUTIL.getKey(rsaKey);
          idToken = jose.KJUR.jws.JWS.sign(
            header.alg,
            JSON.stringify(header),
            JSON.stringify(iPayload),
            // @ts-ignore
            privateKey,
          );
        }

        const tokenResponse: TokenResponse = {
          accessToken,
          tokenType: 'Bearer',
          scope,
          idToken,
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

  // if (req.body.grantType === 'clientCredentials') {
  //   const scope = req.body.scope !== undefined ? req.body.scope.split(' ') : [];
  //   const cScope = client.scope !== undefined ? client.scope.split(' ') : [];
  //   if (hasDiffScope(scope, cScope)) {
  //     res.status(400).json({
  //       error: 'invalidScope',
  //     });
  //     return;
  //   }

  //   const query =
  //     'INSERT INTO `secrets` (`access_token`, `refresh_token`, `client_id`, `scope`) VALUES (?, ?, ?, ?)';
  //   await connection.execute(query, [accessToken, '', clientId, scope]);
  //   await connection.end();

  //   const tokenResponse: TokenResponse = {
  //     accessToken,
  //     tokenType: 'Bearer',
  //     scope: scope.join(' '),
  //   };
  //   res.status(200).json(tokenResponse);
  //   console.log('Issued tokens for code %s', req.body.code);
  //   return;
  // }

  // if (req.body.grantType === 'refreshToken') {
  //   const sql = 'SELECT * FROM `secrets` WHERE `access_token` = ?';
  //   const [rows] = await connection.execute<RowDataPacket[]>(sql, [req.body.refreshToken]);
  //   if (rows.length !== 1) {
  //     const deleteQuery = 'DELETE FROM `secrets` WHERE `refresh_token` = ?';
  //     connection.execute(deleteQuery, [req.body.refreshToken]);
  //     res.status(401).end();
  //     await connection.end();
  //     return;
  //   }
  //   if (rows[0].client_id !== clientId) {
  //     res.status(400).end();
  //     await connection.end();
  //     return;
  //   }
  //   const newAccessToken = randomstring.generate();

  //   const query =
  //     'INSERT INTO `secrets` (`access_token`, `client_id`, `refresh_token`, `scope`) VALUES (?, ?, ?, ?)';
  //   await connection.execute(query, [newAccessToken, clientId, '', '']);
  //   await connection.end();

  //   const tokenResponse: TokenResponse = {
  //     accessToken: newAccessToken,
  //     tokenType: 'Bearer',
  //     refreshToken: req.body.refreshToken,
  //     scope: null,
  //   };
  //   res.status(200).json(tokenResponse);
  //   return;
  // }

  // if (req.body.grantType === 'password') {
  //   const { userName, password } = req.body;
  //   const user = getUser(userName);
  //   if (user === undefined) {
  //     console.log('Unknown user %s', user);
  //     res.status(401).json({
  //       error: 'invalid_grant',
  //     });
  //     return;
  //   }
  //   if (password !== user.password) {
  //     console.log(
  //       'Mismatched resource owner password, expected %s got %s',
  //       user.password,
  //       password,
  //     );
  //     res.status(401).json({
  //       error: 'invalid_grant',
  //     });
  //     return;
  //   }

  //   const scope = req.body.scope !== undefined ? req.body.scope.split(' ') : [];
  //   res.status(200).json(generateTokens(clientId, user, scope));
  //   return;
  // }

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
