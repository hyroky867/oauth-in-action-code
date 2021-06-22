import { Request } from 'express';
import { ParsedQs } from 'qs';

export interface AuthServer {
  authorizationEndpoint: string;
  tokenEndpoint: string;
}

export interface Client {
  clientId: string;
  clientSecret: string;
  redirectUris: string[];
  scope: string;
}

type AuthorizeQueryKeys = 'clientId' | 'redirectUri' | 'scope' | 'error';

export interface AuthorizeRequest extends Request {
  query: {
    [key in AuthorizeQueryKeys]: string;
  };
}

export interface AuthorizeParsedQs extends ParsedQs {
  clientId: string;
  redirectUri: string;
  state?: string;
}

type ApproveBodyKeys = 'reqid' | 'approve' | 'user';

export interface ApproveRequest extends Request {
  body: {
    [key in ApproveBodyKeys]: string;
  };
  query: {
    [key in AuthorizeQueryKeys]: string;
  };
}

export interface Code {
  authorizationEndpointRequest: AuthorizeParsedQs;
  scope: string[];
  user: string;
}

type TokenBodyKeys = 'clientId' | 'clientSecret' | 'grantType' | 'code';

export interface TokenRequest extends Request {
  body: {
    [key in TokenBodyKeys]: string;
  };
}

export type GrantType = 'authorizationCode';

export type ResponseType = 'code';
