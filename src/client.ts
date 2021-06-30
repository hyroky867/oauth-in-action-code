import express, { Request, Response } from 'express';
import cons from 'consolidate';
import qs from 'qs';
import randomstring from 'randomstring';
import axios, { AxiosError, AxiosResponse } from 'axios';
import { URL } from 'url';
import {
  Client,
  AuthServer,
  ResourceResponse,
  TokenResponse,
  State,
  AccessToken,
  Scope,
  RefreshToken,
} from './types/Authorization';

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

let state: State = null;

let accessToken: AccessToken = '987tghjkiu6trfghjuytrghj';
let scope: Scope = null;
let refreshToken: RefreshToken = 'j2r3oj32r23rmasd98uhjrk2o3i';

app.get('/', (_: Request, res: Response): void =>
  res.render('index', {
    accessToken,
    scope,
    refreshToken,
  }),
);

app.get('/authorize', (_: Request, res: Response): void => {
  accessToken = null;
  refreshToken = null;
  scope = null;
  state = randomstring.generate();

  const authorizeUrl = new URL(authServer.authorizationEndpoint);
  authorizeUrl.searchParams.append('responseType', 'code');
  authorizeUrl.searchParams.append('scope', client.scope);
  authorizeUrl.searchParams.append('clientId', client.clientId);
  authorizeUrl.searchParams.append('redirectUri', client.redirectUris[0]);
  authorizeUrl.searchParams.append('state', state);

  return res.redirect(authorizeUrl.toString());
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

  const formData = qs.stringify({
    grantType: 'authorizationCode',
    code: req.query.code,
    redirectUri: client.redirectUris[0],
  });
  const headers = {
    'Content-Type': 'application/x-www-form-urlencoded',
    Authorization: `Basic ${encodeClientCredentials(client.clientId, client.clientSecret)}`,
  };

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

app.get('/fetch_resource', async (_: Request, res: Response): Promise<void> => {
  const headers = {
    'Content-Type': 'application/x-www-form-urlencoded',
    Authorization: `Bearer ${accessToken}`,
  };

  return axios
    .post<ResourceResponse>(protectedResource, null, {
      headers,
    })
    .then((fetchResourceRes: AxiosResponse<ResourceResponse>): void =>
      res.render('data', {
        resource: fetchResourceRes.data.resource,
      }),
    )
    .catch((e: AxiosError): void => {
      const message = e.response?.data || e.message;
      console.log('/fetch_resource: %s', JSON.stringify(e));
      res.render('error', {
        error: `Server returned response code: : ${JSON.stringify(message)}`,
      });
    });
});

app.use('/', express.static('files/client'));

const port = 9000;
const address = '0.0.0.0';

app.listen(port, address, (): void => {
  console.log('OAuth Client is listening at http://%s:%s', address, port);
});
