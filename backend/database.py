"""Storage layer.

Uses MongoDB when MONGO_URI is reachable, otherwise falls back to an in-memory
store so the demo always works (even without Docker/Mongo).
Collections: threats, cves, assets
"""
import os
import sys
import copy
from typing import Optional

COLLECTIONS = ("threats", "cves", "assets", "allowlist", "log_alerts", "source_reputation")


class MemoryStore:
    kind = "memory"

    def __init__(self):
        self.data = {c: {} for c in COLLECTIONS}

    def list(self, coll):
        return [copy.deepcopy(d) for d in self.data.get(coll, {}).values()]

    def get(self, coll, _id) -> Optional[dict]:
        d = self.data.get(coll, {}).get(_id)
        return copy.deepcopy(d) if d else None

    def upsert(self, coll, doc):
        if coll not in self.data:
            self.data[coll] = {}
        self.data[coll][doc["id"]] = copy.deepcopy(doc)
        return doc

    def delete(self, coll, _id) -> bool:
        if coll in self.data and _id in self.data[coll]:
            del self.data[coll][_id]
            return True
        return False

    def clear(self, coll=None):
        for c in ([coll] if coll else COLLECTIONS):
            self.data[c] = {}


class MongoStore:
    kind = "mongodb"

    def __init__(self, uri, db_name):
        from pymongo import MongoClient

        self.client = MongoClient(uri, serverSelectionTimeoutMS=1500)
        self.client.admin.command("ping")  # raises if unreachable
        self.db = self.client[db_name]

    def list(self, coll):
        out = []
        for d in self.db[coll].find({}):
            d["id"] = d.pop("_id")
            out.append(d)
        return out

    def get(self, coll, _id):
        d = self.db[coll].find_one({"_id": _id})
        if d:
            d["id"] = d.pop("_id")
        return d

    def upsert(self, coll, doc):
        body = {k: v for k, v in doc.items() if k != "id"}
        self.db[coll].replace_one({"_id": doc["id"]}, body, upsert=True)
        return doc

    def delete(self, coll, _id) -> bool:
        res = self.db[coll].delete_one({"_id": _id})
        return res.deleted_count > 0

    def clear(self, coll=None):
        for c in ([coll] if coll else COLLECTIONS):
            self.db[c].delete_many({})


def get_store():
    
    uri = os.getenv("MONGO_URI", "mongodb://localhost:27017")
    db_name = os.getenv("MONGO_DB", "cyber_intel")
    if os.getenv("USE_MEMORY_DB") == "1":
        print("[database] USE_MEMORY_DB=1 requested; using in-memory store")
        return MemoryStore()
    try:
        s = MongoStore(uri, db_name)
        print(f"[database] Connected to MongoDB successfully (db: {db_name})")
        return s
    except Exception as e:  # noqa: BLE001
        print(f"[database] MongoDB unavailable ({e.__class__.__name__}: {e}); using in-memory store")
        return MemoryStore()
      
print("[debug] Python executable:", sys.executable)

try:
    import pymongo
    print("[debug] PyMongo version:", pymongo.__version__)
    print("[debug] PyMongo path:", pymongo.__file__)
except ImportError as e:
    print("[debug] PyMongo import failed:", e)


store = get_store()

