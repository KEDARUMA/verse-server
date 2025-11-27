import {Long, Timestamp} from "bson";
import type {User} from "@kedaruma/revlm-shared/models/user-types";

export type RevlmErrorResponse = { ok: false; error: string };
export type LoginSuccess = { ok: true; token: string; user: User };
export type LoginResponse = LoginSuccess | RevlmErrorResponse;
export type ProvisionalLoginSuccess = { ok: true; token: string; user: Record<string, never> };
export type ProvisionalLoginResponse = ProvisionalLoginSuccess | RevlmErrorResponse;
export type RegisterUserSuccess = { ok: true; user: User };
export type RegisterUserResponse = RegisterUserSuccess | RevlmErrorResponse;
export type DeleteUserSuccess = { ok: true; deletedCount: number };
export type DeleteUserResponse = DeleteUserSuccess | RevlmErrorResponse;

export type FindOneOptions = {
  readonly projection?: Record<string, unknown>;
  readonly sort?: Record<string, unknown>;
};

export type FindOptions = FindOneOptions & {
  readonly limit?: number;
};

export type FindOneAndModifyOptions = FindOneOptions & {
  readonly upsert?: boolean;
  readonly returnNewDocument?: boolean;
};

export type CountOptions = {
  readonly limit?: number;
};

export type UpdateOptions = {
  readonly upsert?: boolean;
  readonly arrayFilters?: Filter[];
};

export type Document<IdType = unknown> = {
  _id: IdType;
};

export type NewDocument<T extends Document> = Omit<T, "_id"> & Partial<Pick<T, "_id">>;

export type InsertOneResult<IdType> = {
  readonly insertedId: IdType;
};

export type InsertManyResult<IdType> = {
  readonly insertedIds: IdType[];
};

export type DeleteResult = {
  readonly deletedCount: number;
};

export type UpdateResult<IdType> = {
  readonly matchedCount: number;
  readonly modifiedCount: number;
  readonly upsertedId?: IdType;
};

export type Filter = Record<string, unknown>;
export type Update = Record<string, unknown>;
export type AggregatePipelineStage = Record<string, unknown>;
export type OperationType =
  "insert"
  | "delete"
  | "replace"
  | "update"
  | "drop"
  | "rename"
  | "dropDatabase"
  | "invalidate";

export type DocumentNamespace = {
  db: string;
  coll: string;
};

export type UpdateDescription = {
  updatedFields: Record<string, unknown>;
  removedFields: string[];
};

export type ChangeEventId = unknown;
export type DocumentKey<IdType> = {
  _id: IdType;
} & Record<string, unknown>;

export type BaseChangeEvent<T extends OperationType> = {
  _id: ChangeEventId;
  operationType: T;
  clusterTime: Timestamp;
  txnNumber?: Long;
  lsid?: Record<string, unknown>;
};

export type InsertEvent<T extends Document> = {
  ns: DocumentNamespace;
  documentKey: DocumentKey<T["_id"]>;
  fullDocument: T;
} & BaseChangeEvent<"insert">;

export type UpdateEvent<T extends Document> = {
  ns: DocumentNamespace;
  documentKey: DocumentKey<T["_id"]>;
  updateDescription: UpdateDescription;
  fullDocument?: T;
} & BaseChangeEvent<"update">;

export type ReplaceEvent<T extends Document> = {
  ns: DocumentNamespace;
  documentKey: DocumentKey<T["_id"]>;
  fullDocument: T;
} & BaseChangeEvent<"replace">;

export type DeleteEvent<T extends Document> = {
  ns: DocumentNamespace;
  documentKey: DocumentKey<T["_id"]>;
} & BaseChangeEvent<"delete">;

export type DropEvent = {
  ns: DocumentNamespace;
} & BaseChangeEvent<"drop">;

export type RenameEvent = {
  ns: DocumentNamespace;
  to: DocumentNamespace;
} & BaseChangeEvent<"rename">;

export type DropDatabaseEvent = {
  ns: Omit<DocumentNamespace, "coll">;
} & BaseChangeEvent<"dropDatabase">;

export type InvalidateEvent = BaseChangeEvent<"invalidate">;
export type ChangeEvent<T extends Document> = InsertEvent<T> | UpdateEvent<T> | ReplaceEvent<T> | DeleteEvent<T> | DropEvent | RenameEvent | DropDatabaseEvent | InvalidateEvent;
export type WatchOptionsIds<T extends Document> = {
  ids: T["_id"][];
  filter?: never;
};
export type WatchOptionsFilter = {
  ids?: never;
  filter: Filter;
};
