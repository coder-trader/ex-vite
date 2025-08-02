import express from "express";
import type { Request, Response, Application } from "express";
import { User, UpdateUserRequest, UserParams } from "./types/user.types";

const app: Application = express();
const PORT: number = parseInt(process.env.PORT || "3000");

// Middleware
app.use(express.json());

// Mock users data
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

app.get("/", (_req: Request, res: Response) => {
  res.send("Hello Express with TypeScript!");
});

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
  },
);

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
