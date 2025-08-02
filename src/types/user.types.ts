export interface User {
  id: number;
  name: string;
  email: string;
  role: UserRole;
  createdAt: Date;
  updatedAt: Date;
}

export interface CreateUserRequest {
  name: string;
  email: string;
  password: string;
}

export interface UpdateUserRequest {
  name?: string;
  email?: string;
  role?: UserRole;
}

export interface UserParams {
  id: string;
}

export type UserRole = "user" | "admin" | "moderator";
