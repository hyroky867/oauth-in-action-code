import express, { Request, Response } from 'express';
import cons from 'consolidate';
import qs from 'qs';
import randomstring from 'randomstring';
import axios, { AxiosError, AxiosResponse } from 'axios';
import { URL } from 'url';
import jose from 'jsrsasign';
import base64url from 'base64url';
import {
  TokenRequestPayload,
  RSAKey,
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

const client: Client = {
  clientId: 'oauth-client-1',
  clientSecret: 'oauth-client-secret-1',
  redirectUris: ['http://localhost:9000/callback'],
  scope: 'openid profile email phone address',
};

const authServer: AuthServer = {
  authorizationEndpoint: 'http://0.0.0.0:9001/authorize',
  tokenEndpoint: 'http://authorization:9001/token',
  userInfoEndpoint: 'http://localhost:9001/userinfo',
};

const rsaKey: RSAKey = {
  alg: 'RS256',
  e: 'AQAB',
  n: 'p8eP5gL1H_H9UNzCuQS-vNRVz3NWxZTHYk1tG9VpkfFjWNKG3MFTNZJ1l5g_COMm2_2i_YhQNH8MJ_nQ4exKMXrWJB4tyVZohovUxfw-eLgu1XQ8oYcVYW8ym6Um-BkqwwWL6CXZ70X81YyIMrnsGTyTV6M8gBPun8g2L8KbDbXR1lDfOOWiZ2ss1CRLrmNM-GRp3Gj-ECG7_3Nx9n_s5to2ZtwJ1GS1maGjrSZ9GRAYLrHhndrL_8ie_9DS2T-ML7QNQtNkg2RvLv4f0dpjRYI23djxVtAylYK4oiT_uEMgSkc4dxwKwGuBxSO0g9JOobgfy0--FUHHYtRi0dOFZw',
  kty: 'RSA',
  kid: 'authserver',
};

const protectedResource = 'http://resource:9002/helloWorld';

let state: State = null;

let accessToken: AccessToken = null;
let scope: Scope = null;
let refreshToken: RefreshToken = null;
let idToken = null;
let userInfo = null;

// const registerClient = (): Client => {
//   const template = {
//     clientName: 'OAuth in Action Dynamic Test Client',
//     clientUri: 'http://localhost:9000/',
//     redirectUris: ['http://localhost:9000/callback'],
//     grantTypes: ['authorization_code'],
//     responseTypes: ['code'],
//     tokenEndpointAuthMethod: 'secretBasic',
//     scope: 'openid profile email address phone',
//   };

//   const headers = {
//     'Content-Type': 'application/json',
//     Accept: 'application/json',
//   };

//   const regRes = request('POST', authServer.registrationEndpoint, {
//     body: JSON.stringify(template),
//     headers,
//   });

//   if (regRes.statusCode == 201) {
//     const body = JSON.parse(regRes.getBody());
//     console.log('Got registered client', body);
//     if (body.client_id) {
//       client = body;
//     }
//   }
// };

app.get('/', (_: Request, res: Response): void =>
  res.render('index', {
    accessToken,
    refreshToken,
    scope,
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

  console.log('redirect', authorizeUrl.toString());
  return res.redirect(authorizeUrl.toString());
});

app.get('/callback', (req: Request, res: Response): Promise<void> | void => {
  const { error, code } = req.query;

  if (error !== undefined) {
    console.log('/callback 1: %s', JSON.stringify(error));
    return res.render('error', {
      error,
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
    code,
    redirectUri: client.redirectUris[0],
  });
  const headers = {
    'Content-Type': 'application/x-www-form-urlencoded',
    Authorization: `Basic ${Buffer.from(
      `${escape(client.clientId)}:${escape(client.clientSecret)}`,
    ).toString('base64')}`,
  };

  return axios
    .post<TokenResponse>(authServer.tokenEndpoint, formData, {
      headers,
    })
    .then((tokRes: AxiosResponse<TokenResponse>): void => {
      userInfo = null;
      idToken = null;
      if (tokRes.data.idToken !== undefined) {
        console.log('Got ID token: %s', tokRes.data.idToken);
        const pubKey = jose.KEYUTIL.getKey(rsaKey);
        const tokenParts = tokRes.data.idToken.split('.');
        const payload: TokenRequestPayload = JSON.parse(base64url.decode(tokenParts[1]));
        console.log('Payload', payload);
        if (
          jose.KJUR.jws.JWS.verify(
            tokRes.data.idToken,
            // @ts-ignore
            pubKey,
            [rsaKey.alg],
          )
        ) {
          console.log('Signature validated.');
          if (payload.iss === 'http://localhost:9001/') {
            console.log('issuer OK');
            if (
              (Array.isArray(payload.aud) && payload.aud.includes(client.clientId)) ||
              payload.aud === client.clientId
            ) {
              console.log('Audience OK');

              const now = Math.floor(Date.now() / 1000);

              if (payload.iat <= now) {
                console.log('issued-at OK');
                if (payload.exp >= now) {
                  console.log('expiration OK');

                  console.log('Token valid!');

                  // save just the payload, not the container (which has been validated)
                  idToken = payload;
                }
              }
            }
          }
        }
        res.render('userinfo', {
          userInfo,
          idToken,
        });
        return;
      }

      refreshToken = tokRes.data.refreshToken;
      scope = tokRes.data.scope ?? null;
      accessToken = tokRes.data.accessToken;
      console.log('Got access token: %s', accessToken);
      res.render('index', {
        accessToken,
        refreshToken,
        scope,
      });
    })
    .catch((e: AxiosError): void => {
      const message = e.response?.data || e.message;
      console.log('/callback 2: %s', JSON.stringify(e));
      res.render('error', {
        error: `Unable to fetch access token, server response: ${JSON.stringify(message)}`,
      });
    });
});

app.get('/fetch_resource', async (_: Request, res: Response): Promise<void> => {
  if (accessToken === null) {
    return res.render('error', {
      error: 'Missing access token.',
    });
  }

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

app.get('/userinfo', (_: Request, res: Response): Promise<void> => {
  const headers = {
    'Content-Type': 'application/x-www-form-urlencoded',
    Authorization: `Bearer ${accessToken}`,
  };

  return axios
    .get<ResourceResponse>(authServer.userInfoEndpoint, {
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
