import { ObjectId } from 'bson';
import { DefaultId, MongoDocBase } from './mongo-doc-base-types';

export interface UserBase extends MongoDocBase {
  _id?: DefaultId;
  authId: string;
  passwordHash?: string;
  userType: 'provisional' | 'staff' | 'customer' | '...etc';
  roles?: string[];
  merchantId?: ObjectId;
}

export interface User extends UserBase {}

