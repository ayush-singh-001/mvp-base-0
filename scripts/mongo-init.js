db = db.getSiblingDB('docverifier');

db.createUser({
  user: process.env.MONGO_USER || 'docverify_user',
  pwd: process.env.MONGO_PASSWORD || 'changeme',
  roles: [
    {
      role: 'readWrite',
      db: 'docverifier'
    }
  ]
});

db.createCollection('documents');
db.documents.createIndex({ docHash: 1 }, { unique: true });
db.documents.createIndex({ createdAt: 1 });
