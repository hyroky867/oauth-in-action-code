import express, { NextFunction, Response, Request } from 'express';
import cons from 'consolidate';
import cors from 'cors';
import mysql, { RowDataPacket } from 'mysql2/promise';
import { Resource } from './types/Authorization';

const app = express();

app.use(
  express.urlencoded({
    extended: true,
  }),
);

app.engine('html', cons.underscore);
app.set('view engine', 'html');
app.set('views', 'files/protectedResource');
app.set('json spaces', 4);

app.use('/', express.static('files/protectedResource'));
app.use(cors());

const resource: Resource = {
  name: 'Protected Resource',
  description: 'This data has been protected by OAuth 2.0',
};

app.options('/resource', [cors()]);

const getAccessToken = async (req: Request, _: Response, next: NextFunction): Promise<void> => {
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

  const connection = await mysql.createConnection({
    host: 'db',
    user: 'developer',
    database: 'oAuth',
    port: 3306,
    password: 'root',
  });

  const sql = 'SELECT `access_token` FROM `secrets` WHERE `access_token` = ?';
  try {
    const [rows] = await connection.execute<RowDataPacket[]>(sql, [inToken]);
    console.log(inToken, rows[0].access_token);
    if (inToken !== rows[0].access_token) {
      throw new Error(`mismatch token: ${inToken}`);
    }
    // @ts-ignore
    req.accessToken = inToken;
  } catch (e) {
    console.log(e);
  } finally {
    connection.end();
    next();
  }
};

app.post('/resource', [cors(), getAccessToken], (req: Request, res: Response): void => {
  // @ts-ignore
  if (req.accessToken !== undefined) {
    res.json({
      resource,
      // @ts-ignore
      scope: req.accessToken.scope,
    });
    return;
  }
  res.status(401).end();
});

const port = 9002;
const address = '0.0.0.0';

app.listen(port, address, () => {
  console.log('OAuth Resource Server is listening at http://%s:%s', address, port);
});
