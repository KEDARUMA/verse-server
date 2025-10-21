import Revlm from "revlm-client/Revlm";
import {
  AggregatePipelineStage, ChangeEvent, CountOptions, DeleteResult,
  Filter,
  FindOneAndModifyOptions,
  FindOneOptions,
  FindOptions, InsertManyResult, InsertOneResult, NewDocument,
  Update, UpdateOptions, UpdateResult, WatchOptionsFilter, WatchOptionsIds,
  Document
} from "revlm-client/Revlm.types";

export default class RevlmCollection<T extends Document = Document> {
  private _revlm: Revlm;
  private _dbName: string;
  private _collection: string;

  constructor(collection: string, dbName: string, revlm: Revlm) {
    this._collection = collection;
    this._dbName = dbName;
    this._revlm = revlm;
  }

  get name(): string {
    return this._collection;
  }

  // Helper to call server revlm-gate and return parsed result or throw on error
  private async vg(method: string, params: Record<string, any> = {}): Promise<any> {
    const payload = { db: this._dbName, collection: this._collection, method, ...params };
    const res = await this._revlm.revlmGate(payload);
    if (!res || !res.ok) {
      const errMsg = res && (res.error || res.reason) ? (res.error || res.reason) : 'revlm-gate error';
      const e: any = new Error(String(errMsg));
      e.response = res;
      throw e;
    }
    return res.result;
  }

  async find(filter?: Filter, options?: FindOptions): Promise<T[]> {
    const result = await this.vg('find', { filter: filter || {}, options: options || {} });
    return Array.isArray(result) ? result as T[] : (result || []) as T[];
  }
  async findOne(filter?: Filter, options?: FindOneOptions): Promise<T | null> {
    const result = await this.vg('findOne', { filter: filter || {}, options: options || {} });
    return (result === undefined ? null : result) as T | null;
  }
  async findOneAndUpdate(filter: Filter, update: Update, options?: FindOneAndModifyOptions): Promise<T | null> {
    const result = await this.vg('findOneAndUpdate', { filter, update, options: options || {} });
    // driver often returns an object (e.g. { value: doc, ok: 1 }), try to unwrap
    return (result && (result.value ?? result)) as T | null;
  }
  async findOneAndReplace(filter: Filter, replacement: unknown, options?: FindOneAndModifyOptions): Promise<T | null> {
    const result = await this.vg('findOneAndReplace', { filter, replacement, options: options || {} });
    return (result && (result.value ?? result)) as T | null;
  }
  async findOneAndDelete(filter?: Filter, options?: FindOneOptions): Promise<T | null> {
    const result = await this.vg('findOneAndDelete', { filter: filter || {}, options: options || {} });
    return (result && (result.value ?? result)) as T | null;
  }
  async aggregate(pipeline: AggregatePipelineStage[]): Promise<unknown> {
    return await this.vg('aggregate', { pipeline });
  }
  async count(filter?: Filter, options?: CountOptions): Promise<number> {
    const result = await this.vg('count', { filter: filter || {}, options: options || {} });
    return Number(result || 0);
  }
  async insertOne(document: NewDocument<T>): Promise<InsertOneResult<T["_id"]>> {
    const result = await this.vg('insertOne', { document });
    return result as InsertOneResult<T["_id"]>;
  }
  async insertMany(documents: NewDocument<T>[]): Promise<InsertManyResult<T["_id"]>> {
    const result = await this.vg('insertMany', { documents });
    return result as InsertManyResult<T["_id"]>;
  }
  async deleteOne(filter?: Filter): Promise<DeleteResult> {
    const result = await this.vg('deleteOne', { filter: filter || {} });
    return result as DeleteResult;
  }
  async deleteMany(filter?: Filter): Promise<DeleteResult> {
    const result = await this.vg('deleteMany', { filter: filter || {} });
    return result as DeleteResult;
  }
  async updateOne(filter: Filter, update: Update, options?: UpdateOptions): Promise<UpdateResult<T["_id"]>> {
    const result = await this.vg('updateOne', { filter, update, options: options || {} });
    return result as UpdateResult<T["_id"]>;
  }
  async updateMany(filter: Filter, update: Update, options?: UpdateOptions): Promise<UpdateResult<T["_id"]>> {
    const result = await this.vg('updateMany', { filter, update, options: options || {} });
    return result as UpdateResult<T["_id"]>;
  }
  // single watch implementation with optional options
  async *watch(options?: WatchOptionsIds<T> | WatchOptionsFilter): AsyncGenerator<ChangeEvent<T>> {
    const arr: any = await this.vg('watch', { options: options || {} }) || [];
    for (const it of (Array.isArray(arr) ? arr : [])) {
      yield it as ChangeEvent<T>;
    }
  }
}
