import { ObjectId } from 'bson';

export type DefaultId = ObjectId | string

// 全てのドキュメントの基底インターフェイス
export interface MongoDocBase {
  version: string
  _id?: DefaultId
  collectionType: string
  isRemove: boolean
  timestamp?: Date
  createTime?: Date
  body?: any
}
