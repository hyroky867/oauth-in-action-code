import express, { Express, Response, Request } from 'express';
import bodyParser from 'body-parser';
import cons from 'consolidate';
import _ from 'underscore';
import _s from 'underscore.string';
import cors from 'cors';
// @ts-ignore
import nosql from 'nosql';

import { AccessTokenRequest } from './types/Authorization';
import { NextFunction } from 'express-serve-static-core';

nosql.load('database.nosql');

const app: Express = express();

app.use(
  bodyParser.urlencoded({
    extended: true,
  }),
); // support form-encoded bodies (for bearer tokens)

app.engine('html', cons.underscore);
app.set('view engine', 'html');
app.set('views', 'files/protectedResource');
app.set('json spaces', 4);

app.use('/', express.static('files/protectedResource'));
app.use(cors());

const resource: {
  name: string;
  description: string;
} = {
  name: 'Protected Resource',
  description: 'This data has been protected by OAuth 2.0',
};

const getAccessToken = (req: AccessTokenRequest, _: Response, next: NextFunction): void => {
  // check the auth header first
  const auth = req.headers['authorization'];
  let inToken: string | null = null;
  if (auth && auth.toLowerCase().indexOf('bearer') === 0) {
    inToken = auth.slice('bearer '.length);
  } else if (req.body && req.body.access_token) {
    // not in the header, check in the form body
    inToken = req.body.access_token;
  } else if (req.query && req.query.access_token) {
    inToken = req.query.access_token;
  }

  console.log('Incoming token: %s', inToken);
  nosql.one().make((builder) => {
    builder.where('access_token', inToken);
    builder.callback((err, token) => {
      if (token) {
        console.log('We found a matching token: %s', inToken);
      } else {
        console.log('No matching token was found.');
      }
      req.accessToken = token;
      next();
      return;
    });
  });
};

app.options('/resource', cors());
app.post('/resource', cors(), getAccessToken, (req: AccessTokenRequest, res: Response): void => {
  // app.post('/resource', cors(), getAccessToken, (req: AccessTokenRequest, res) => {
  if (req.accessToken) {
    res.json(resource);
  } else {
    res.status(401).end();
  }
});

const port = 9002;
const host = 'localhost';

app.listen(port, host, () => {
  console.log('OAuth Resource Server is listening at http://%s:%s', host, port);
});
