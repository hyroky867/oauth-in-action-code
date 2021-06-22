import express, { NextFunction, Response, Request } from 'express';
import bodyParser from 'body-parser';
import cons from 'consolidate';
import cors from 'cors';
import mysql from 'mysql2';

const app = express();

app.use(
  bodyParser.urlencoded({
    extended: true,
  }),
);

app.engine('html', cons.underscore);
app.set('view engine', 'html');
app.set('views', 'files/protectedResource');
app.set('json spaces', 4);

app.use('/', express.static('files/protectedResource'));
app.use(cors());

export interface Resource {
  name: string;
  description: string;
}

const resource: Resource = {
  name: 'Protected Resource',
  description: 'This data has been protected by OAuth 2.0',
};

app.options('/resource', [cors()]);

const getAccessToken = (req: Request, _: Response, next: NextFunction): void => {
  // check the auth header first
  const auth = req.headers.authorization;
  let inToken = null;
  if (auth && auth.toLowerCase().indexOf('bearer') === 0) {
    inToken = auth.slice('bearer '.length);
  } else if (req.body?.accessToken) {
    // not in the header, check in the form body
    inToken = req.body.accessToken;
  } else if (req.query?.accessToken) {
    inToken = req.query.accessToken;
  }

  console.log('Incoming token: %s', inToken);
  // nosql.one().make((builder) => {
  //   console.log(builder);
  //   builder.where('accessToken', inToken);
  //   builder.callback((token) => {
  //     if (token) {
  //       console.log('We found a matching token: %s', inToken);
  //     } else {
  //       console.log('No matching token was found.');
  //     }
  //     req.accessToken = token;
  //     next();
  //   });
  // });

  const connection = mysql.createConnection({
    host: '0.0.0.0',
    user: 'developer',
    database: 'oAuth',
    port: 3306,
    password: 'root',
  });

  const query = 'SELECT `access_token` FROM `secrets` WHERE `access_token` = ? ';
  const result = connection.execute(query, [inToken]);
  // @ts-ignore
  req.accessToken = 'hoge';
  return next();
};

app.post('/resource', [cors(), getAccessToken], (req: Request, res: Response) => {
  // @ts-ignore
  if (req.accessToken !== undefined) {
    return res.json(resource);
  }
  return res.status(401).end();
});

const port = 9002;
const address = '0.0.0.0';

app.listen(port, address, () => {
  console.log('OAuth Resource Server is listening at http://%s:%s', address, port);
});
