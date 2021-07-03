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
  revocationEndpoint?: string;
  registrationEndpoint?: string;
  userInfoEndpoint?: string;
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

export interface AuthorizeParsedQs extends ParsedQs {
  clientId: string;
  redirectUri: string;
  state?: string;
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
  // scope: string[];
  // user: string;
}

export interface TokenRequest extends Request {
  body: {
    clientId: string;
    clientSecret: string;
    grantType: GrantType;
    code: string;
    scope: string;
    refreshToken: string;
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
  alg: string;
  e: string;
  n: string;
  kty: string;
  kid: string;
}
