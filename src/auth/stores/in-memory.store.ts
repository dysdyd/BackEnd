import { Injectable } from '@nestjs/common';

export interface User {
    id: string;
    email: string;
    passwordHash: string;
    createdAt: Date;
}

export interface Session {
    userId: string;
    deviceEnv: string; // Combined IP + UserAgent or similar identifier
    token: string;
    lastActive: Date;
}

@Injectable()
export class InMemoryStore {
    // Key: User ID -> User Object
    private users = new Map<string, User>();

    // Key: Email -> User ID (Index for fast login lookup)
    private emailIndex = new Map<string, string>();

    // Key: User ID -> Session Object
    // Only one session per user allowed as per requirement
    private sessions = new Map<string, Session>();

    createUser(user: User): void {
        this.users.set(user.id, user);
        this.emailIndex.set(user.email, user.id);
    }

    findUserByEmail(email: string): User | undefined {
        const userId = this.emailIndex.get(email);
        if (!userId) return undefined;
        return this.users.get(userId);
    }

    findUserById(id: string): User | undefined {
        return this.users.get(id);
    }

    createSession(userId: string, session: Session): void {
        // Overwrite existing session for this user
        this.sessions.set(userId, session);
    }

    findSession(userId: string): Session | undefined {
        return this.sessions.get(userId);
    }

    deleteSession(userId: string): void {
        this.sessions.delete(userId);
    }
}
