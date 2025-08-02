import request from 'supertest';
import express from 'express';
import type { Request, Response } from 'express';
import { User, UpdateUserRequest, UserParams } from '../src/types/user.types';

// Create a test version of the app
function createTestApp() {
  const app = express();
  app.use(express.json());

  // Mock users data (same as in server.ts)
  let users: User[] = [
    {
      id: 1,
      name: "John Doe",
      email: "john.doe@example.com",
      role: "user",
      createdAt: new Date("2024-01-15"),
      updatedAt: new Date("2024-01-15"),
    },
    {
      id: 2,
      name: "Jane Smith",
      email: "jane.smith@example.com",
      role: "admin",
      createdAt: new Date("2024-01-10"),
      updatedAt: new Date("2024-01-20"),
    },
    {
      id: 3,
      name: "Bob Wilson",
      email: "bob.wilson@example.com",
      role: "moderator",
      createdAt: new Date("2024-01-05"),
      updatedAt: new Date("2024-01-18"),
    },
    {
      id: 4,
      name: "Alice Brown",
      email: "alice.brown@example.com",
      role: "user",
      createdAt: new Date("2024-01-12"),
      updatedAt: new Date("2024-01-12"),
    },
  ];

  // Routes
  app.get("/users", (_req: Request, res: Response<User[]>) => {
    res.json(users);
  });

  app.put(
    "/users/:id",
    (req: Request<UserParams, User, UpdateUserRequest>, res: Response<User>) => {
      const userId = parseInt(req.params.id);
      const updates = req.body;

      // Validate user ID
      if (isNaN(userId) || userId <= 0) {
        return res.status(400).json({
          error: "Invalid user ID",
        } as any);
      }

      // Find user
      const userIndex = users.findIndex((user) => user.id === userId);
      if (userIndex === -1) {
        return res.status(404).json({
          error: "User not found",
        } as any);
      }

      // Update user
      const updatedUser: User = {
        ...users[userIndex],
        ...updates,
        updatedAt: new Date(),
      };

      users[userIndex] = updatedUser;
      res.json(updatedUser);
    }
  );

  return app;
}

describe('GET /users', () => {
  let app: express.Application;

  beforeEach(() => {
    app = createTestApp();
  });

  describe('Successful requests', () => {
    it('should return 200 status code', async () => {
      const response = await request(app)
        .get('/users')
        .expect(200);
    });

    it('should return an array of users', async () => {
      const response = await request(app)
        .get('/users')
        .expect(200);

      expect(Array.isArray(response.body)).toBe(true);
      expect(response.body.length).toBe(4);
    });

    it('should return users with correct structure', async () => {
      const response = await request(app)
        .get('/users')
        .expect(200);

      const user = response.body[0];
      expect(user).toHaveProperty('id');
      expect(user).toHaveProperty('name');
      expect(user).toHaveProperty('email');
      expect(user).toHaveProperty('role');
      expect(user).toHaveProperty('createdAt');
      expect(user).toHaveProperty('updatedAt');
    });

    it('should return users with correct data types', async () => {
      const response = await request(app)
        .get('/users')
        .expect(200);

      const user = response.body[0];
      expect(typeof user.id).toBe('number');
      expect(typeof user.name).toBe('string');
      expect(typeof user.email).toBe('string');
      expect(typeof user.role).toBe('string');
      expect(typeof user.createdAt).toBe('string'); // JSON serializes dates as strings
      expect(typeof user.updatedAt).toBe('string');
    });

    it('should return users with valid roles', async () => {
      const response = await request(app)
        .get('/users')
        .expect(200);

      const validRoles = ['user', 'admin', 'moderator'];
      response.body.forEach((user: User) => {
        expect(validRoles).toContain(user.role);
      });
    });

    it('should return users with valid email format', async () => {
      const response = await request(app)
        .get('/users')
        .expect(200);

      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      response.body.forEach((user: User) => {
        expect(emailRegex.test(user.email)).toBe(true);
      });
    });

    it('should return users with unique IDs', async () => {
      const response = await request(app)
        .get('/users')
        .expect(200);

      const userIds = response.body.map((user: User) => user.id);
      const uniqueIds = new Set(userIds);
      expect(uniqueIds.size).toBe(userIds.length);
    });

    it('should return users with unique emails', async () => {
      const response = await request(app)
        .get('/users')
        .expect(200);

      const userEmails = response.body.map((user: User) => user.email);
      const uniqueEmails = new Set(userEmails);
      expect(uniqueEmails.size).toBe(userEmails.length);
    });
  });

  describe('Response format', () => {
    it('should return Content-Type application/json', async () => {
      const response = await request(app)
        .get('/users')
        .expect(200);

      expect(response.headers['content-type']).toMatch(/application\/json/);
    });

    it('should return expected user data', async () => {
      const response = await request(app)
        .get('/users')
        .expect(200);

      const expectedUser = {
        id: 1,
        name: "John Doe",
        email: "john.doe@example.com",
        role: "user",
        createdAt: "2024-01-15T00:00:00.000Z",
        updatedAt: "2024-01-15T00:00:00.000Z",
      };

      expect(response.body[0]).toEqual(expectedUser);
    });

    it('should return all expected users in correct order', async () => {
      const response = await request(app)
        .get('/users')
        .expect(200);

      const expectedUsers = [
        { id: 1, name: "John Doe", role: "user" },
        { id: 2, name: "Jane Smith", role: "admin" },
        { id: 3, name: "Bob Wilson", role: "moderator" },
        { id: 4, name: "Alice Brown", role: "user" }
      ];

      expectedUsers.forEach((expectedUser, index) => {
        const actualUser = response.body[index];
        expect(actualUser.id).toBe(expectedUser.id);
        expect(actualUser.name).toBe(expectedUser.name);
        expect(actualUser.role).toBe(expectedUser.role);
      });
    });
  });

  describe('Performance and edge cases', () => {
    it('should handle multiple concurrent requests', async () => {
      const promises = Array.from({ length: 10 }, () =>
        request(app).get('/users').expect(200)
      );

      const responses = await Promise.all(promises);
      
      responses.forEach(response => {
        expect(response.body.length).toBe(4);
      });
    });

    it('should not modify the original users array', async () => {
      const response1 = await request(app)
        .get('/users')
        .expect(200);

      const response2 = await request(app)
        .get('/users')
        .expect(200);

      expect(response1.body).toEqual(response2.body);
    });

    it('should return consistent data across multiple requests', async () => {
      const response1 = await request(app).get('/users');
      const response2 = await request(app).get('/users');
      const response3 = await request(app).get('/users');

      expect(response1.body).toEqual(response2.body);
      expect(response2.body).toEqual(response3.body);
    });
  });

  describe('Data validation', () => {
    it('should have positive integer IDs', async () => {
      const response = await request(app)
        .get('/users')
        .expect(200);

      response.body.forEach((user: User) => {
        expect(user.id).toBeGreaterThan(0);
        expect(Number.isInteger(user.id)).toBe(true);
      });
    });

    it('should have non-empty names', async () => {
      const response = await request(app)
        .get('/users')
        .expect(200);

      response.body.forEach((user: User) => {
        expect(user.name.trim()).not.toBe('');
        expect(user.name.length).toBeGreaterThan(0);
      });
    });

    it('should have valid date formats', async () => {
      const response = await request(app)
        .get('/users')
        .expect(200);

      response.body.forEach((user: User) => {
        expect(new Date(user.createdAt).toString()).not.toBe('Invalid Date');
        expect(new Date(user.updatedAt).toString()).not.toBe('Invalid Date');
      });
    });

    it('should have updatedAt >= createdAt', async () => {
      const response = await request(app)
        .get('/users')
        .expect(200);

      response.body.forEach((user: User) => {
        const createdAt = new Date(user.createdAt);
        const updatedAt = new Date(user.updatedAt);
        expect(updatedAt.getTime()).toBeGreaterThanOrEqual(createdAt.getTime());
      });
    });
  });
});