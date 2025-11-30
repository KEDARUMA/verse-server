import { BSON, ObjectID, ObjectId } from '../index';

describe('BSON compatibility exports', () => {
  it('provides ObjectID alias that matches ObjectId constructor', () => {
    const id = new BSON.ObjectID();
    expect(id).toBeInstanceOf(BSON.ObjectId);
    expect(id).toBeInstanceOf(ObjectId);
    expect(id).toBeInstanceOf(ObjectID);
    expect(String(id)).toHaveLength(24);
  });

  it('exposes BSON namespace with ObjectID', () => {
    expect(BSON.ObjectID).toBeDefined();
    const fromBson = new BSON.ObjectID();
    const fromTop = new ObjectID();
    expect(String(fromBson)).not.toBe('');
    expect(String(fromTop)).toHaveLength(24);
  });
});
