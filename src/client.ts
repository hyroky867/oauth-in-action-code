import express, { Request, Response } from 'express';
import cons from 'consolidate';
import __ from 'underscore';
import qs from 'qs';
import randomstring from 'randomstring';
import axios, { AxiosError, AxiosResponse } from 'axios';
import { Resource } from './protectedResource';
import { Client, AuthServer } from './types/Authorization';

const app = express();

app.engine('html', cons.underscore);
app.set('view engine', 'html');
app.set('views', 'files/client');

const authServer: AuthServer = {
  authorizationEndpoint: 'http://0.0.0.0:9001/authorize',
  tokenEndpoint: 'http://authorization:9001/token',
};

const client: Client = {
  clientId: 'oauth-client-1',
  clientSecret: 'oauth-client-secret-1',
  redirectUris: ['http://0.0.0.0:9000/callback'],
  scope: 'foo',
};

const protectedResource = 'http://resource:9002/resource';

let state: string | null = null;

let accessToken: string | null = '987tghjkiu6trfghjuytrghj';
let scope: string | null = null;
let refreshToken: string | null = 'j2r3oj32r23rmasd98uhjrk2o3i';

app.get('/', (_: Request, res: Response): void =>
  res.render('index', {
    accessToken,
    scope,
    refreshToken,
  }),
);

interface BuildUrlParams {
  base: string;
  options: {
    [key: string]: string;
  };
  hash?: string;
}

const buildUrl = ({ base, options, hash }: BuildUrlParams): string => {
  const newUrl = new URL(base);
  __.each(options, (value: string, key: string) => {
    newUrl.searchParams.append(key, value);
  });
  if (hash !== undefined) {
    newUrl.searchParams.append('hash', hash);
  }
  return newUrl.toString();
};

app.get('/authorize', (_: Request, res: Response): void => {
  accessToken = null;
  scope = null;
  state = randomstring.generate();

  const options = {
    responseType: 'code',
    scope: client.scope,
    clientId: client.clientId,
    redirectUri: client.redirectUris[0],
    state,
  };
  const authorizeUrl = buildUrl({
    base: authServer.authorizationEndpoint,
    options,
  });

  console.log('redirect', authorizeUrl);
  return res.redirect(authorizeUrl);
});

const encodeClientCredentials = (clientId: string, clientSecret: string) =>
  Buffer.from(`${escape(clientId)}:${escape(clientSecret)}`).toString('base64');

app.get('/callback', (req: Request, res: Response): Promise<void> | void => {
  if (req.query.error !== undefined) {
    console.log('/callback 1: %s', JSON.stringify(req.query.error));
    return res.render('error', {
      error: req.query.error,
    });
  }

  const resState = req.query.state;
  if (resState !== state) {
    console.log('State DOES NOT MATCH: expected %s got %s', state, resState);
    return res.render('error', {
      error: 'State value did not match',
    });
  }

  const { code } = req.query;

  const formData = qs.stringify({
    grantType: 'authorizationCode',
    code,
    redirectUri: client.redirectUris[0],
  });
  const headers = {
    'Content-Type': 'application/x-www-form-urlencoded',
    Authorization: `Basic ${encodeClientCredentials(client.clientId, client.clientSecret)}`,
  };

  interface TokenResponse {
    accessToken: string;
    scope: string;
    refreshToken: string;
  }

  return axios
    .post<TokenResponse>(authServer.tokenEndpoint, formData, {
      headers,
    })
    .then((tokRes: AxiosResponse<TokenResponse>): void => {
      refreshToken = tokRes.data.refreshToken;
      scope = tokRes.data.scope;
      accessToken = tokRes.data.accessToken;
    })
    .catch((e: AxiosError): void => {
      const message = e.response?.data || e.message;
      console.log('/callback 2: %s', JSON.stringify(e));
      res.render('error', {
        // error: `Unable to fetch access token, server response: ${e.response?.status}`,
        error: `Unable to fetch access token, server response: ${JSON.stringify(message)}`,
      });
    })
    .finally((): void =>
      res.render('index', {
        accessToken,
        scope,
        refreshToken,
      }),
    );
});

const refreshAccessToken = async (_: Request, res: Response): Promise<void> => {
  const formData = qs.stringify({
    grantType: 'refreshToken',
    refreshToken,
  });
  const headers = {
    'Content-Type': 'application/x-www-form-urlencoded',
    Authorization: `Basic ${encodeClientCredentials(client.clientId, client.clientSecret)}`,
  };

  interface RefreshTokenResponse {
    accessToken: string;
    refreshToken: string;
    scope: string;
  }

  try {
    const tokRes = await axios.post<RefreshTokenResponse>(
      authServer.authorizationEndpoint,
      formData,
      {
        headers,
      },
    );
    refreshToken = tokRes.data.refreshToken;
    scope = tokRes.data.scope;
    accessToken = tokRes.data.accessToken;
    return res.redirect('/fetch_resource');
  } catch (e) {
    refreshToken = null;
    return res.render('error', {
      error: 'Unable to refresh token.',
    });
  }
};

app.get('/fetch_resource', async (req: Request, res: Response): Promise<void> => {
  const headers = {
    Authorization: `Bearer ${accessToken}`,
    'Content-Type': 'application/x-www-form-urlencoded',
  };

  interface ResourceResponse {
    resource: Resource;
  }

  try {
    await axios.post<ResourceResponse>(protectedResource, null, {
      headers,
    });
    return await refreshAccessToken(req, res);
  } catch (e) {
    const message = e.response?.data || e.message;
    console.log('/fetch_resource 2: %s', JSON.stringify(e));
    return res.render('error', {
      // error: `Unable to fetch access token, server response: ${e.response?.status}`,
      error: `Unable to fetch access token, server response: ${JSON.stringify(message)}`,
    });
  }
});

app.use('/', express.static('files/client'));

const port = 9000;
const address = '0.0.0.0';

app.listen(port, address, (): void => {
  console.log('OAuth Client is listening at http://%s:%s', address, port);
});
