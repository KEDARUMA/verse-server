import Verse from "verse-client/Verse";
import VerseCollection from "verse-client/VerseCollection";
import { Document } from "./Verse.types";

export default class VerseDBDatabase {
  private _verse: Verse;
  private _dbName: string;

  constructor(dbName: string, verse: Verse) {
    this._dbName = dbName;
    this._verse = verse;
  }

  collection<T extends Document = Document>(collection: string): VerseCollection<T> {
    return new VerseCollection<T>(collection, this._dbName, this._verse);
  }
}
