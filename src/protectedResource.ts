import express, { NextFunction, Response, Request } from 'express';
import cons from 'consolidate';
import cors from 'cors';
import mysql, { RowDataPacket } from 'mysql2/promise';
import { Resource, UserInfoKeyType, UserInfoProfileKey } from './types/Authorization';

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

app.options('/resource', [cors()]);

app.post('/resource', [cors(), getAccessToken], (req: Request, res: Response): void => {
  // @ts-ignore
  if (req.accessToken !== undefined) {
    res.json({
      resource,
    });
    return;
  }
  res.status(401).end();
});

const requireAccessToken = (req: Request, res: Response, next: NextFunction): void => {
  // @ts-ignore
  if (req.accessToken !== undefined) {
    return next();
  }
  return res.status(401).end();
};

const userInfoEndpoint = (req: Request, res: Response): void => {
  // @ts-ignore
  const { accessToken, user, scope } = req;
  if (accessToken.scope.contains('openid')) {
    res.status(403).end();
    return;
  }

  if (user === undefined) {
    res.status(404).end();
    return;
  }

  const profileClaim = [
    'name',
    'family_name',
    'given_name',
    'middle_name',
    'nickname',
    'preferred_username',
    'profile',
    'picture',
    'website',
    'gender',
    'birthdate',
    'zoneinfo',
    'locale',
    'updated_at',
  ];

  const result = scope.forEach<
    {
      [key in UserInfoKeyType]: string;
    }
  >((item: string) => {
    if (item === 'openid' && user) {
      ['sub'].forEach((claim) => {
        if (user[claim] !== undefined) {
          result[claim] = user[claim];
        }
      });
    } else if (item === 'profile') {
      profileClaim.forEach((claim) => {
        if (user[claim]) {
          result[claim] = user[claim];
        }
      });
    } else if (item === 'email') {
      ['email', 'emailVerified'].forEach((claim) => {
        if (user[claim]) {
          result[claim] = user[claim];
        }
      });
    } else if (item === 'address') {
      ['address'].forEach((claim) => {
        if (user[claim]) {
          result[claim] = user[claim];
        }
      });
    } else if (item === 'phone') {
      ['phoneNumber', 'phoneNumberVerified'].forEach((claim) => {
        if (user[claim]) {
          result[claim] = user[claim];
        }
      });
    }
  });

  res.status(200).json(result);
};

app.get('/userinfo', [getAccessToken, requireAccessToken, userInfoEndpoint]);
app.post('/userinfo', [getAccessToken, requireAccessToken, userInfoEndpoint]);

const port = 9002;
const address = '0.0.0.0';

app.listen(port, address, () => {
  console.log('OAuth Resource Server is listening at http://%s:%s', address, port);
});
