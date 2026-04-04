"use strict";

// Dependencies
const crypto = require("crypto")
const path = require("path")
const fs = require("fs")

// Main
class Collection {
    constructor(collectionPath) {
        this.collectionPath = collectionPath
        if (!this.collectionPath.endsWith(".json")) this.collectionPath += ".json"
        if (!fs.existsSync(this.collectionPath)) fs.writeFileSync(this.collectionPath, JSON.stringify([], null, 2), "utf8")
    }

    _read() {
        try {
            const data = fs.readFileSync(this.collectionPath, "utf8")
            return JSON.parse(data)
        } catch {
            return []
        }
    }

    _write(data) {
        fs.writeFileSync(this.collectionPath, JSON.stringify(data, null, 2), "utf8")
    }

    _match(doc, query) {
        if (!query || !Object.keys(query).length) return true
        for (const [key, value] of Object.entries(query)) if (doc[key] !== value) return false
        return true
    }

    _applyUpdate(doc, update) {
        // Variables
        const hasOperators = Object.keys(update).some((k) => k.startsWith("$"))
        const updateSet = update.$set || (!hasOperators ? update : null)

        // Core
        if (updateSet) for (const [key, value] of Object.entries(updateSet)) if (key !== "_id") doc[key] = value
        if (update.$push) {
            for (const [key, value] of Object.entries(update.$push)) {
                if (!Array.isArray(doc[key])) doc[key] = []
                if (value && typeof value === "object" && Array.isArray(value.$each)) {
                    doc[key].push(...value.$each)
                } else {
                    doc[key].push(value)
                }
            }
        }

        if (update.$pull) {
            for (const [key, value] of Object.entries(update.$pull)) {
                if (Array.isArray(doc[key])) {
                    doc[key] = doc[key].filter((item) => {
                        if (typeof value === "object" && value !== null && !Array.isArray(value)) {
                            return !this._match(item, value)
                        } else {
                            return item !== value
                        }
                    })
                }
            }
        }
    }

    insertOne(doc) {
        const data = this._read()
        const newDoc = { _id: crypto.randomUUID(), ...doc }
        data.push(newDoc)
        this._write(data)
        return { acknowledged: true, insertedId: newDoc._id, doc: newDoc }
    }

    insertMany(docs) {
        // Variables
        if (!Array.isArray(docs)) throw new Error("insertMany requires an array of documents.")
        const data = this._read()
        const newDocs = docs.map((doc) => ({ _id: crypto.randomUUID(), ...doc }))

        // Core
        data.push(...newDocs)
        this._write(data)
        return { acknowledged: true, insertedCount: newDocs.length, insertedIds: newDocs.map(d => d._id) }
    }

    findOne(query = {}) {
        const data = this._read()
        const found = data.find((doc) => this._match(doc, query))
        return found || null
    }

    findMany(query = {}) {
        const data = this._read()
        return data.filter((doc) => this._match(doc, query))
    }

    updateOne(query, update) {
        // Variables
        const data = this._read()
        const index = data.findIndex((doc) => this._match(doc, query))

        // Core
        if (index !== -1) {
            this._applyUpdate(data[index], update)
            this._write(data)
            return { acknowledged: true, matchedCount: 1, modifiedCount: 1 }
        }

        return { acknowledged: true, matchedCount: 0, modifiedCount: 0 }
    }

    updateMany(query, update) {
        // Variables
        const data = this._read()
        var modifiedCount = 0
        var matchedCount = 0

        // Core
        for (var i = 0; i < data.length; i++) {
            if (this._match(data[i], query)) {
                matchedCount++
                this._applyUpdate(data[i], update)
                modifiedCount++
            }
        }

        if (modifiedCount > 0) this._write(data)

        return { acknowledged: true, matchedCount, modifiedCount }
    }

    deleteOne(query) {
        // Variables
        const data = this._read()
        const index = data.findIndex((doc) => this._match(doc, query))

        // Core
        if (index !== -1) {
            data.splice(index, 1)
            this._write(data)
            return { acknowledged: true, deletedCount: 1 }
        }

        return { acknowledged: true, deletedCount: 0 }
    }

    deleteMany(query) {
        // Variables
        const data = this._read()
        const initialLength = data.length

        const newData = data.filter((doc) => !this._match(doc, query))
        const deletedCount = initialLength - newData.length

        // Core
        if (deletedCount > 0) this._write(newData)
        return { acknowledged: true, deletedCount }
    }
}

class Database {
    constructor(dbPath) {
        this.dbPath = dbPath
        if (!fs.existsSync(this.dbPath)) fs.mkdirSync(this.dbPath, { recursive: true })
    }

    collection(name) {
        const safeName = path.basename(name)
        const collectionPath = path.join(this.dbPath, safeName)
        return new Collection(collectionPath)
    }
}

class LocalMongo {
    constructor(basePath) {
        this.basePath = basePath
        if (!fs.existsSync(this.basePath)) fs.mkdirSync(this.basePath, { recursive: true })
    }

    db(name) {
        const safeName = path.basename(name)
        const dbPath = path.join(this.basePath, safeName)
        return new Database(dbPath)
    }
}

module.exports = { LocalMongo }