import { ObjectId } from 'bson';
import {DefaultId, MongoDocBase} from "./mongo-doc-base-types";

export interface UserBase extends MongoDocBase {
  _id?: DefaultId // Base interface for all documents
  authId: string
  passwordHash?: string
  userType: 'provisional' | 'staff' | 'customer' | '...etc';　// Base interface for all documents
  roles?: string[]　// Base interface for all documents
  merchantId?: ObjectId　// Base interface for all documents
}

export interface User extends UserBase {
}
