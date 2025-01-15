import mongoose from 'mongoose';
import { MongoClient, Db } from 'mongodb';

const uri = "mongodb+srv://veterano:wilson17@cluster0.ocdjg.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0";

const clientOptions = { serverApi: { version: "1" as const, strict: true, deprecationErrors: true } };

const connectDB = async () => {
    try {
        await mongoose.connect(uri, clientOptions);
        if (mongoose.connection.db) {
            await mongoose.connection.db.admin().command({ ping: 1 });
        } else {
            throw new Error("Database connection is undefined");
        }
        console.log("Pinged your deployment. You successfully connected to MongoDB!");
    } catch (err) {
        if (err instanceof Error) {
            console.error(err.message);
        } else {
            console.error(err);
        }
        process.exit(1);
    }
};

let db: Db;

export const connectToDb = async (uri: string) => {
    const client = new MongoClient(uri);
    await client.connect();
    db = client.db();
};

export const getDb = (): Db => {
    if (!db) {
        throw new Error('Database not connected');
    }
    return db;
};

export default connectDB;
