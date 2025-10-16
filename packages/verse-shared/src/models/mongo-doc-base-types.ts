import { ObjectId } from 'bson';

export type DefaultId = ObjectId | string

export interface MongoDocBase {
  _id?: DefaultId
}

