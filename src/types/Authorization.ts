import { Request } from 'express';
import { ParsedQs } from 'qs';

export type State = string | null;
export type AccessToken = string | null;
export type Scope = string | null;
export type RefreshToken = string | null;
export type IDToken = string | null;

export interface AuthServer {
  authorizationEndpoint: string;
  tokenEndpoint: string;
  userInfoEndpoint: string;
}

export interface Client {
  clientId: string;
  clientSecret: string;
  redirectUris: string[];
  scope: string;
}

export interface AuthorizeRequest extends Request {
  query: {
    clientId: string;
    redirectUri: string;
    scope: string;
    error: string;
  };
}

export type ResponseType = 'code' | 'token';

export interface AuthorizeParsedQs extends ParsedQs {
  clientId: string;
  redirectUri: string;
  state?: string;
  responseType?: ResponseType;
}

export interface ApproveRequestBody {
  reqid: string;
  approve: string;
  user: string;
}

export interface ApproveRequest extends Request {
  body: ApproveRequestBody;
  query: {
    clientId: string;
    redirectUri: string;
    scope: string;
    error: string;
  };
}

export interface Code {
  request: AuthorizeParsedQs;
  scope: string[];
  // user: string;
  user: User;
}

export interface TokenRequest extends Request {
  body: {
    clientId: string;
    clientSecret: string;
    grantType: GrantType;
    code: Code;
    scope: Scope;
    refreshToken: RefreshToken;
    userName: string;
    password: string;
  };
}

export type GrantType = 'authorizationCode' | 'clientCredentials' | 'refreshToken' | 'password';

export interface User {
  sub: string;
  preferredUsername: string;
  name: string;
  email: string;
  emailVerified: boolean;
  userName?: string;
  password?: string;
}

export type TokenType = 'Bearer';

export interface TokenResponse {
  accessToken: AccessToken;
  tokenType: TokenType;
  refreshToken: RefreshToken;
  scope?: Scope;
  state?: State;
  idToken?: string;
}

export interface Resource {
  name: string;
  description: string;
}

export interface ResourceResponse {
  resource: Resource;
}

export interface ClientCredential {
  id: string;
  secret: string;
}

export interface RSAKey {
  alg: TokenRequestALG;
  e: string;
  d: string;
  n: string;
  kty: string;
  kid: string;
}

export interface ProtectedResource {
  resourceId: string;
  resourceSecret: string;
}

export type TokenRequestType = 'JWT';
export type TokenRequestALG = 'RS256';

export interface TokenRequestHeader {
  typ: TokenRequestType;
  alg: TokenRequestALG;
  kid: string;
}

export interface TokenRequestPayload {
  iss: string;
  sub: string;
  aud: string;
  iat: number;
  exp: number;
  nonce?: any;
}

export type UserInfoProfileKey =
  | 'name'
  | 'familyName'
  | 'givenName'
  | 'middleName'
  | 'nickname'
  | 'preferredUsername'
  | 'profile'
  | 'picture'
  | 'website'
  | 'gender'
  | 'birthdate'
  | 'zoneinfo'
  | 'locale'
  | 'updatedAt';

export type UserInfoEmailType = 'email' | 'emailVerified';

export type UserInfoPhoneType = 'phoneNumber' | 'phoneNumberVerified';

export type UserInfoKeyType =
  | 'sub'
  | UserInfoProfileKey
  | UserInfoEmailType
  | 'address'
  | UserInfoPhoneType;
