import express, { Express, Response, Request } from 'express';
import cons from 'consolidate';
import _, { has, string } from 'underscore';
import _s from 'underscore.string';
import { AuthServer, Client } from './types/Authorization';
// @ts-ignore
import nosql from 'nosql';

nosql.load('database.nosql');

const app: Express = express();

app.engine('html', cons.underscore);
app.set('view engine', 'html');
app.set('views', 'files/client');

// authorization server information
const authServer: AuthServer = {
  authorizationEndpoint: 'http://localhost:9001/authorize',
  tokenEndpoint: 'http://localhost:9001/token',
};

// client information
const client: Client = {
  clientId: 'oauth-client-1',
  clientSecret: 'oauth-client-secret-1',
  redirectUris: ['http://localhost:9000/callback'],
};

const protectedResource = 'http://localhost:9002/resource';

app.get('/', (req: Request, res: Response): void => {
  res.render('index', {
    access_token: null,
    scope: null,
  });
});

app.get('/authorize', (req, res) => {
  /*
   * Send the user to the authorization server
   */
});

app.get('/callback', function (req, res) {
  /*
   * Parse the response from the authorization server and get a token
   */
});

app.get('/fetch_resource', function (req, res) {
  /*
   * Use the access token to call the resource server
   */
});

interface BuildUrlParams {
  base: string;
  options: {
    [key: string]: string;
  };
  hash?: string;
}

const buildUrl = ({ base, options, hash }: BuildUrlParams): string => {
  const newUrl = new URL(base);

  _.each(options, (value: string, key: string) => {
    newUrl.searchParams.append(key, value);
  });
  if (hash) {
    newUrl.searchParams.append('hash', hash);
  }

  return newUrl.toString();
};

const encodeClientCredentials = (clientId: string, clientSecret: string) => {
  const escapedClientId = escape(clientId);
  const escapedClientSecret = escape(clientSecret);
  return Buffer.from(`${escapedClientId}:${escapedClientSecret}`).toString('base64');
};

app.use('/', express.static('files/client'));

const port = 9000;
const host = 'localhost';

app.listen(port, host, () => {
  console.log(`OAuth Client is listening at http://%${host}:${port}`);
});
