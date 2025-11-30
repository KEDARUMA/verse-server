import * as bson from 'bson';

// Re-export ObjectId with an ObjectID alias to mirror legacy Realm usage.
export const ObjectId = bson.ObjectId;
export const ObjectID = bson.ObjectId;

// Provide a BSON namespace that also exposes ObjectID for compatibility.
export const BSON = Object.assign({}, bson, { ObjectID: bson.ObjectId });

export default BSON;
