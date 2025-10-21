import Revlm from "revlm-client/Revlm";
import RevlmCollection from "revlm-client/RevlmCollection";
import { Document } from "./Revlm.types";

export default class RevlmDBDatabase {
  private _revlm: Revlm;
  private _dbName: string;

  constructor(dbName: string, revlm: Revlm) {
    this._dbName = dbName;
    this._revlm = revlm;
  }

  collection<T extends Document = Document>(collection: string): RevlmCollection<T> {
    return new RevlmCollection<T>(collection, this._dbName, this._revlm);
  }
}
