import express, { Express, Response, Request } from 'express';
import bodyParser from 'body-parser';
import cons from 'consolidate';
import _ from 'underscore';
import _s from 'underscore.string';
import randomstring from 'randomstring';
// @ts-ignore
import nosql from 'nosql';
import {
  AuthServer,
  Client,
  AuthorizeRequest,
  ApproveRequest,
  AuthorizeParsedQs,
  TokenRequest,
  Code,
} from './types/Authorization';

nosql.load('database.nosql');

const app: Express = express();

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
const authServer: AuthServer = {
  authorizationEndpoint: 'http://localhost:9001/authorize',
  tokenEndpoint: 'http://localhost:9001/token',
};

// client information
const clients: Client[] = [
  {
    clientId: 'oauth-client-1',
    clientSecret: 'oauth-client-secret-1',
    redirectUris: ['http://localhost:9000/callback'],
    scope: 'foo bar',
  },
];

const getClient = (clientId: string) =>
  _.find(clients, (client: Client) => client.clientId === clientId);

app.get('/', (_: Request, res: Response): void => {
  res.render('index', {
    clients,
    authServer,
  });
});

const requests: {
  [key: string]: AuthorizeParsedQs;
} = {};

app.get('/authorize', (req: AuthorizeRequest, res: Response): void => {
  const client = getClient(req.query.client_id);

  if (!client) {
    console.log('Unknown client %s', req.query.client_id);
    res.render('error', { error: 'Unknown client' });
  } else if (!_.contains(client.redirectUris, req.query.redirect_uri)) {
    console.log(
      'Mismatched redirect URI, expected %s got %s',
      client.redirectUris,
      req.query.redirect_uri,
    );
    res.render('error', {
      error: 'Invalid redirect URI',
    });
  } else {
    const rscope = req.query.scope ? req.query.scope.split(' ') : '';
    const cscope = client.scope ? client.scope.split(' ') : '';
    if (_.difference(rscope, cscope).length > 0) {
      // client asked for a scope it couldn't have
      const url = new URL(req.query.redirect_uri);
      url.searchParams.append('error', 'invalid_scope');
      res.redirect(url.toString());
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

const codes: {
  [key: string]: Code;
} = {};

app.post('/approve', (req: ApproveRequest, res: Response): void => {
  const { reqid } = req.body;
  const query = requests[reqid];
  delete requests[reqid];

  if (!query) {
    // there was no matching saved request, this is an error
    res.render('error', {
      error: 'No matching authorization request',
    });
    return;
  }

  const url = new URL(query.redirect_uri);
  if (req.body.approve) {
    if (query.response_type === 'code') {
      // user approved access
      const code = randomstring.generate(8);

      const { user } = req.body;

      const scope = _.filter(_.keys(req.body), (s: string) => _s.startsWith(s, 'scope_')).map(
        (s: string) => s.slice('scope_'.length),
      );

      const client = getClient(query.client_id);
      if (client === undefined) {
        res.render('error', {
          error: 'No matching authorization request',
        });
        return;
      }

      const cscope = client.scope ? client.scope.split(' ') : '';
      if (_.difference(scope, cscope).length > 0) {
        // client asked for a scope it couldn't have
        url.searchParams.append('error', 'invalid_scope');

        res.redirect(url.toString());
        return;
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

      res.redirect(url.toString());
    } else {
      // we got a response type we don't understand
      url.searchParams.append('error', 'unsupported_response_type');
      res.redirect(url.toString());
    }
  } else {
    // user denied access
    url.searchParams.append('error', 'access_denied');
    res.redirect(url.toString());
  }
});

app.post('/token', (req: TokenRequest, res: Response): void => {
  const auth = req.headers.authorization;
  let clientId = '';
  let clientSecret = '';
  if (auth) {
    // check the auth header
    const clientCredentials = Buffer.from(auth.slice('basic '.length), 'base64')
      .toString()
      .split(':');
    clientId = unescape(clientCredentials[0]);
    clientSecret = unescape(clientCredentials[1]);
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
    res.status(401).json({
      error: 'invalid_client',
    });
    return;
  }

  if (client.clientSecret != clientSecret) {
    console.log('Mismatched client secret, expected %s got %s', client.clientSecret, clientSecret);
    res.status(401).json({
      error: 'invalid_client',
    });
    return;
  }

  if (req.body.grant_type === 'authorization_code') {
    const code = codes[req.body.code];

    if (code) {
      delete codes[req.body.code]; // burn our code, it's been used
      if (code.authorizationEndpointRequest.client_id == clientId) {
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
        res.status(400).json({
          error: 'invalid_grant',
        });
      }
    } else {
      console.log('Unknown code, %s', req.body.code);
      res.status(400).json({
        error: 'invalid_grant',
      });
    }
  } else {
    console.log('Unknown grant type %s', req.body.grant_type);
    res.status(400).json({
      error: 'unsupported_grant_type',
    });
  }
});
