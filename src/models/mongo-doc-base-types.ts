import { ObjectId } from 'bson';

export type DefaultId = ObjectId | string

// Base interface for all documents
export interface MongoDocBase {
  _id?: DefaultId
}
