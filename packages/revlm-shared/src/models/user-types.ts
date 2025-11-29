import { ObjectId } from 'bson';
import { DefaultId, MongoDocBase } from './mongo-doc-base-types.js';

export enum DefaultUserType {
  Provisional = 'provisional',
}

// Allow consumer-defined strings while providing a default enum
export type UserType = DefaultUserType | (string & {});

export interface UserBase extends MongoDocBase {
  _id?: DefaultId;
  authId: string;
  passwordHash?: string;
  userType: UserType;
  roles?: string[];
}

export interface User extends UserBase {}
