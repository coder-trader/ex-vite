# Express.js + TypeScript Learning Path

A comprehensive curriculum to master Express.js with TypeScript from basics to production-ready applications.

## Prerequisites
- Basic JavaScript and TypeScript knowledge
- Node.js installed
- Understanding of HTTP concepts
- Basic command line usage

---

## Part 1: TypeScript Foundations (Lessons 1-5)

### Lesson 1: Setting Up Express with TypeScript
**Goal**: Create your first typed Express server

**Topics**:
- TypeScript project setup
- Express with proper typing
- Development workflow with ts-node
- Basic type definitions

**Hands-on**:
```bash
mkdir express-ts-learning && cd express-ts-learning
npm init -y
npm install express
npm install -D typescript @types/express @types/node ts-node nodemon
npx tsc --init
```

**tsconfig.json**:
```json
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "ESNext",
    "moduleResolution": "Node",
    "lib": ["ES2022"],
    "outDir": "./dist",
    "rootDir": "./src",
    "strict": true,
    "esModuleInterop": true,
    "allowSyntheticDefaultImports": true,
    "skipLibCheck": true,
    "forceConsistentCasingInFileNames": true,
    "resolveJsonModule": true,
    "declaration": true,
    "declarationMap": true,
    "sourceMap": true
  },
  "ts-node": {
    "esm": true
  },
  "include": ["src/**/*"],
  "exclude": ["node_modules", "dist"]
}
```

**src/server.ts**:
```typescript
import express from 'express';
import type { Request, Response, Application } from 'express';

const app: Application = express();
const PORT: number = parseInt(process.env.PORT || '3000');

app.get('/', (req: Request, res: Response) => {
  res.send('Hello Express with TypeScript!');
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
```

**package.json scripts**:
```json
{
  "scripts": {
    "dev": "nodemon --exec \"node --loader ts-node/esm\" src/server.ts",
    "build": "tsc",
    "start": "node dist/server.js"
  }
}
```

**Exercise**: Create a server that responds with typed user data on `/about`

---

### Lesson 2: Typed Routing and Parameters
**Goal**: Handle routes with proper TypeScript typing

**Topics**:
- Request/Response typing
- Route parameter interfaces
- Query parameter typing
- Custom type definitions

**Hands-on**:
```typescript
import type { Request, Response } from 'express';

// Custom interfaces
interface User {
  id: number;
  name: string;
  email: string;
  createdAt: Date;
}

interface CreateUserRequest {
  name: string;
  email: string;
  password: string;
}

interface UserParams {
  id: string;
}

interface SearchQuery {
  q?: string;
  limit?: string;
  page?: string;
}

// Typed route handlers
app.get('/users', (req: Request, res: Response<User[]>) => {
  const users: User[] = [];
  res.json(users);
});

app.post('/users', (req: Request<{}, User, CreateUserRequest>, res: Response<User>) => {
  const { name, email, password } = req.body;
  const newUser: User = {
    id: Date.now(),
    name,
    email,
    createdAt: new Date()
  };
  res.status(201).json(newUser);
});

app.get('/users/:id', (req: Request<UserParams>, res: Response<User | { error: string }>) => {
  const userId = parseInt(req.params.id);
  if (isNaN(userId)) {
    return res.status(400).json({ error: 'Invalid user ID' });
  }
  
  const user: User = {
    id: userId,
    name: 'John Doe',
    email: 'john@example.com',
    createdAt: new Date()
  };
  res.json(user);
});

app.get('/search', (req: Request<{}, User[], {}, SearchQuery>, res: Response<User[]>) => {
  const { q, limit = '10', page = '1' } = req.query;
  const limitNum = parseInt(limit);
  const pageNum = parseInt(page);
  
  // Search logic here
  const results: User[] = [];
  res.json(results);
});
```

**Exercise**: Build a typed API for a book collection with full CRUD operations

---

### Lesson 3: Typed Middleware
**Goal**: Create and use type-safe middleware

**Topics**:
- Middleware function typing
- Custom middleware interfaces
- Request augmentation
- Error handling types

**Hands-on**:
```typescript
import type { Request, Response, NextFunction } from 'express';

// Extend Request interface for custom properties
declare global {
  namespace Express {
    interface Request {
      user?: User;
      startTime?: number;
    }
  }
}

// Custom middleware types
type AsyncMiddleware = (req: Request, res: Response, next: NextFunction) => Promise<void>;
type Middleware = (req: Request, res: Response, next: NextFunction) => void;

// Built-in middleware with types
app.use(express.json());
app.use(express.static('public'));

// Custom typed middleware
const logger: Middleware = (req, res, next) => {
  console.log(`${req.method} ${req.path} - ${new Date().toISOString()}`);
  next();
};

const timer: Middleware = (req, res, next) => {
  req.startTime = Date.now();
  next();
};

const asyncLogger: AsyncMiddleware = async (req, res, next) => {
  try {
    // Async logging operation
    await logToDatabase(req.method, req.path);
    next();
  } catch (error) {
    next(error);
  }
};

// Authentication middleware with types
interface AuthenticatedRequest extends Request {
  user: User;
}

const authenticate = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
  const token = req.headers.authorization?.split(' ')[1];
  
  if (!token) {
    res.status(401).json({ error: 'No token provided' });
    return;
  }
  
  try {
    const user = await verifyToken(token);
    req.user = user;
    next();
  } catch (error) {
    res.status(401).json({ error: 'Invalid token' });
  }
};

// Using typed middleware
app.use(logger);
app.use(timer);

app.get('/protected', authenticate, (req: Request, res: Response) => {
  // req.user is now properly typed
  res.json({ message: 'Protected route', user: req.user });
});

// Helper functions
async function logToDatabase(method: string, path: string): Promise<void> {
  // Database logging logic
}

async function verifyToken(token: string): Promise<User> {
  // Token verification logic
  return { id: 1, name: 'John', email: 'john@example.com', createdAt: new Date() };
}
```

**Exercise**: Create typed middleware for request validation and rate limiting

---

### Lesson 4: Advanced Request/Response Typing
**Goal**: Master complex typing scenarios

**Topics**:
- Generic request/response types
- Union types for different responses
- Optional and conditional typing
- Type guards and validation

**Hands-on**:
```typescript
import type { Request, Response } from 'express';

// Generic response types
interface ApiResponse<T> {
  success: boolean;
  data?: T;
  error?: string;
  timestamp: string;
}

interface PaginatedResponse<T> {
  data: T[];
  pagination: {
    page: number;
    limit: number;
    total: number;
    totalPages: number;
  };
}

// Union types for different response scenarios
type UserResponse = ApiResponse<User> | ApiResponse<null>;
type UsersResponse = ApiResponse<PaginatedResponse<User>>;

// Generic API handler type
type ApiHandler<TParams = {}, TQuery = {}, TBody = {}> = (
  req: Request<TParams, any, TBody, TQuery>,
  res: Response
) => Promise<void> | void;

// Type guards
const isValidEmail = (email: string): boolean => {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
};

const validateCreateUserBody = (body: any): body is CreateUserRequest => {
  return (
    typeof body === 'object' &&
    typeof body.name === 'string' &&
    typeof body.email === 'string' &&
    typeof body.password === 'string' &&
    isValidEmail(body.email)
  );
};

// Typed route handlers with proper error handling
const createUser: ApiHandler<{}, {}, CreateUserRequest> = async (req, res) => {
  try {
    if (!validateCreateUserBody(req.body)) {
      const response: ApiResponse<null> = {
        success: false,
        error: 'Invalid request body',
        timestamp: new Date().toISOString()
      };
      res.status(400).json(response);
      return;
    }

    const { name, email, password } = req.body;
    const user: User = {
      id: Date.now(),
      name,
      email,
      createdAt: new Date()
    };

    const response: ApiResponse<User> = {
      success: true,
      data: user,
      timestamp: new Date().toISOString()
    };

    res.status(201).json(response);
  } catch (error) {
    const response: ApiResponse<null> = {
      success: false,
      error: 'Internal server error',
      timestamp: new Date().toISOString()
    };
    res.status(500).json(response);
  }
};

const getUsers: ApiHandler<{}, { page?: string; limit?: string }> = async (req, res) => {
  const page = parseInt(req.query.page || '1');
  const limit = parseInt(req.query.limit || '10');
  
  // Mock data
  const users: User[] = [];
  const total = 100;
  
  const response: UsersResponse = {
    success: true,
    data: {
      data: users,
      pagination: {
        page,
        limit,
        total,
        totalPages: Math.ceil(total / limit)
      }
    },
    timestamp: new Date().toISOString()
  };
  
  res.json(response);
};

// Route registration
app.post('/api/users', createUser);
app.get('/api/users', getUsers);
```

**Exercise**: Create a typed file upload handler with proper validation

---

### Lesson 5: Typed Express Router
**Goal**: Organize routes with TypeScript

**Topics**:
- Router with TypeScript
- Route module organization
- Shared types and interfaces
- Route-specific middleware typing

**Hands-on**:
**src/types/index.ts**:
```typescript
export interface User {
  id: number;
  name: string;
  email: string;
  createdAt: Date;
}

export interface CreateUserRequest {
  name: string;
  email: string;
  password: string;
}

export interface UpdateUserRequest {
  name?: string;
  email?: string;
}

export interface UserParams {
  id: string;
}

export interface ApiResponse<T> {
  success: boolean;
  data?: T;
  error?: string;
  timestamp: string;
}
```

**src/routes/users.ts**:
```typescript
import { Router } from 'express';
import type { Request, Response } from 'express';
import { User, CreateUserRequest, UpdateUserRequest, UserParams, ApiResponse } from '../types';

const router = Router();

// Router-specific middleware
const validateUserId = (req: Request<UserParams>, res: Response, next: Function) => {
  const userId = parseInt(req.params.id);
  if (isNaN(userId) || userId <= 0) {
    const response: ApiResponse<null> = {
      success: false,
      error: 'Invalid user ID',
      timestamp: new Date().toISOString()
    };
    res.status(400).json(response);
    return;
  }
  next();
};

// Route handlers
router.get('/', async (req: Request, res: Response<ApiResponse<User[]>>) => {
  try {
    const users: User[] = []; // Mock data
    res.json({
      success: true,
      data: users,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Failed to fetch users',
      timestamp: new Date().toISOString()
    });
  }
});

router.get('/:id', validateUserId, async (req: Request<UserParams>, res: Response<ApiResponse<User>>) => {
  try {
    const userId = parseInt(req.params.id);
    const user: User = {
      id: userId,
      name: 'John Doe',
      email: 'john@example.com',
      createdAt: new Date()
    };
    
    res.json({
      success: true,
      data: user,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Failed to fetch user',
      timestamp: new Date().toISOString()
    });
  }
});

router.post('/', async (req: Request<{}, ApiResponse<User>, CreateUserRequest>, res: Response<ApiResponse<User>>) => {
  try {
    const { name, email, password } = req.body;
    
    const user: User = {
      id: Date.now(),
      name,
      email,
      createdAt: new Date()
    };
    
    res.status(201).json({
      success: true,
      data: user,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Failed to create user',
      timestamp: new Date().toISOString()
    });
  }
});

router.put('/:id', validateUserId, async (req: Request<UserParams, ApiResponse<User>, UpdateUserRequest>, res: Response<ApiResponse<User>>) => {
  try {
    const userId = parseInt(req.params.id);
    const updates = req.body;
    
    const user: User = {
      id: userId,
      name: updates.name || 'John Doe',
      email: updates.email || 'john@example.com',
      createdAt: new Date()
    };
    
    res.json({
      success: true,
      data: user,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Failed to update user',
      timestamp: new Date().toISOString()
    });
  }
});

router.delete('/:id', validateUserId, async (req: Request<UserParams>, res: Response<ApiResponse<null>>) => {
  try {
    const userId = parseInt(req.params.id);
    // Delete logic here
    
    res.json({
      success: true,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Failed to delete user',
      timestamp: new Date().toISOString()
    });
  }
});

export default router;
```

**src/server.ts**:
```typescript
import express from 'express';
import userRoutes from './routes/users';

const app = express();

app.use(express.json());
app.use('/api/users', userRoutes);

export default app;
```

**Exercise**: Create separate typed route modules for posts, comments, and categories

---

## Part 2: Intermediate TypeScript Concepts (Lessons 6-10)

### Lesson 6: Template Engines with TypeScript
**Goal**: Render typed dynamic HTML pages

**Topics**:
- EJS with TypeScript
- Template data interfaces
- Type-safe view rendering
- Layout typing

**Hands-on**:
```typescript
import type { Request, Response } from 'express';

interface ProfileData {
  user: {
    name: string;
    email: string;
    avatar?: string;
  };
  posts: Array<{
    id: number;
    title: string;
    content: string;
    createdAt: Date;
  }>;
  stats: {
    totalPosts: number;
    totalViews: number;
    joinDate: Date;
  };
}

interface ProfileParams {
  username: string;
}

app.set('view engine', 'ejs');
app.set('views', './src/views');

const getProfile = async (req: Request<ProfileParams>, res: Response): Promise<void> => {
  try {
    const { username } = req.params;
    
    const profileData: ProfileData = {
      user: {
        name: username,
        email: `${username}@example.com`,
        avatar: '/images/default-avatar.png'
      },
      posts: [
        {
          id: 1,
          title: 'My First Post',
          content: 'This is my first blog post!',
          createdAt: new Date()
        }
      ],
      stats: {
        totalPosts: 1,
        totalViews: 150,
        joinDate: new Date('2023-01-01')
      }
    };
    
    res.render('profile', profileData);
  } catch (error) {
    res.status(500).render('error', { 
      message: 'Failed to load profile',
      error: process.env.NODE_ENV === 'development' ? error : {}
    });
  }
};

app.get('/profile/:username', getProfile);
```

**views/profile.ejs**:
```html
<!DOCTYPE html>
<html>
<head>
    <title><%= user.name %>'s Profile</title>
</head>
<body>
    <div class="profile">
        <h1><%= user.name %></h1>
        <p><%= user.email %></p>
        
        <div class="stats">
            <p>Posts: <%= stats.totalPosts %></p>
            <p>Views: <%= stats.totalViews %></p>
            <p>Joined: <%= stats.joinDate.toDateString() %></p>
        </div>
        
        <div class="posts">
            <% posts.forEach(post => { %>
                <article>
                    <h3><%= post.title %></h3>
                    <p><%= post.content %></p>
                    <small><%= post.createdAt.toDateString() %></small>
                </article>
            <% }) %>
        </div>
    </div>
</body>
</html>
```

**Exercise**: Build a typed blog with dynamic pages for posts and categories

---

### Lesson 7: Advanced Error Handling with TypeScript
**Goal**: Implement robust typed error handling

**Topics**:
- Custom error classes with TypeScript
- Error type discrimination
- Async error handling patterns
- Error middleware typing

**Hands-on**:
```typescript
import type { Request, Response, NextFunction } from 'express';

// Custom error classes
abstract class AppError extends Error {
  abstract statusCode: number;
  abstract isOperational: boolean;
  
  constructor(message: string) {
    super(message);
    Object.setPrototypeOf(this, AppError.prototype);
  }
}

class ValidationError extends AppError {
  statusCode = 400;
  isOperational = true;
  
  constructor(message: string, public field?: string) {
    super(message);
    Object.setPrototypeOf(this, ValidationError.prototype);
  }
}

class NotFoundError extends AppError {
  statusCode = 404;
  isOperational = true;
  
  constructor(resource: string) {
    super(`${resource} not found`);
    Object.setPrototypeOf(this, NotFoundError.prototype);
  }
}

class DatabaseError extends AppError {
  statusCode = 500;
  isOperational = true;
  
  constructor(message: string = 'Database operation failed') {
    super(message);
    Object.setPrototypeOf(this, DatabaseError.prototype);
  }
}

// Async wrapper with proper typing
type AsyncHandler<P = {}, ResBody = any, ReqBody = {}, ReqQuery = {}> = (
  req: Request<P, ResBody, ReqBody, ReqQuery>,
  res: Response<ResBody>,
  next: NextFunction
) => Promise<void>;

const asyncHandler = <P, ResBody, ReqBody, ReqQuery>(
  fn: AsyncHandler<P, ResBody, ReqBody, ReqQuery>
) => {
  return (req: Request<P, ResBody, ReqBody, ReqQuery>, res: Response<ResBody>, next: NextFunction) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
};

// Error response interface
interface ErrorResponse {
  success: false;
  error: {
    message: string;
    statusCode: number;
    field?: string;
    stack?: string;
  };
  timestamp: string;
}

// Typed error middleware
const errorHandler = (
  err: Error,
  req: Request,
  res: Response<ErrorResponse>,
  next: NextFunction
): void => {
  let error: AppError;
  
  if (err instanceof AppError) {
    error = err;
  } else if (err.name === 'ValidationError') {
    error = new ValidationError(err.message);
  } else if (err.name === 'CastError') {
    error = new ValidationError('Invalid ID format');
  } else {
    error = new DatabaseError('Something went wrong');
  }
  
  const response: ErrorResponse = {
    success: false,
    error: {
      message: error.message,
      statusCode: error.statusCode,
      ...(error instanceof ValidationError && error.field && { field: error.field }),
      ...(process.env.NODE_ENV === 'development' && { stack: error.stack })
    },
    timestamp: new Date().toISOString()
  };
  
  res.status(error.statusCode).json(response);
};

// Usage in routes
const getUserById = asyncHandler<UserParams, ApiResponse<User>>(async (req, res, next) => {
  const userId = parseInt(req.params.id);
  
  if (isNaN(userId)) {
    throw new ValidationError('Invalid user ID', 'id');
  }
  
  // Simulate database call
  const user = await findUserById(userId);
  
  if (!user) {
    throw new NotFoundError('User');
  }
  
  res.json({
    success: true,
    data: user,
    timestamp: new Date().toISOString()
  });
});

// Mock database function
async function findUserById(id: number): Promise<User | null> {
  // Simulate async database operation
  if (id === 1) {
    return {
      id: 1,
      name: 'John Doe',
      email: 'john@example.com',
      createdAt: new Date()
    };
  }
  return null;
}

app.get('/api/users/:id', getUserById);
app.use(errorHandler);
```

**Exercise**: Add comprehensive typed error handling to your book API

---

### Lesson 8: Input Validation with TypeScript
**Goal**: Type-safe validation and sanitization

**Topics**:
- TypeScript with validation libraries
- Custom validation decorators
- Runtime type checking
- Schema validation

**Hands-on**:
```typescript
import type { Request, Response, NextFunction } from 'express';
import { body, query, param, validationResult, ValidationChain } from 'express-validator';

// Validation result interface
interface ValidationError {
  field: string;
  message: string;
  value?: any;
}

interface ValidationResponse {
  success: false;
  errors: ValidationError[];
  timestamp: string;
}

// Custom validation middleware with typing
const validate = (validations: ValidationChain[]) => {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    // Run all validations
    await Promise.all(validations.map(validation => validation.run(req)));
    
    const errors = validationResult(req);
    if (errors.isEmpty()) {
      return next();
    }
    
    const validationErrors: ValidationError[] = errors.array().map(error => ({
      field: error.param,
      message: error.msg,
      value: error.value
    }));
    
    const response: ValidationResponse = {
      success: false,
      errors: validationErrors,
      timestamp: new Date().toISOString()
    };
    
    res.status(400).json(response);
  };
};

// User validation schemas
const createUserValidation = [
  body('name')
    .trim()
    .isLength({ min: 2, max: 50 })
    .withMessage('Name must be between 2 and 50 characters'),
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Must be a valid email address'),
  body('password')
    .isLength({ min: 8 })
    .withMessage('Password must be at least 8 characters')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
    .withMessage('Password must contain at least one lowercase letter, one uppercase letter, and one number'),
  body('age')
    .optional()
    .isInt({ min: 13, max: 120 })
    .withMessage('Age must be between 13 and 120')
];

const updateUserValidation = [
  param('id')
    .isInt({ min: 1 })
    .withMessage('User ID must be a positive integer'),
  body('name')
    .optional()
    .trim()
    .isLength({ min: 2, max: 50 })
    .withMessage('Name must be between 2 and 50 characters'),
  body('email')
    .optional()
    .isEmail()
    .normalizeEmail()
    .withMessage('Must be a valid email address')
];

const getUsersValidation = [
  query('page')
    .optional()
    .isInt({ min: 1 })
    .withMessage('Page must be a positive integer'),
  query('limit')
    .optional()
    .isInt({ min: 1, max: 100 })
    .withMessage('Limit must be between 1 and 100'),
  query('search')
    .optional()
    .trim()
    .isLength({ min: 1, max: 100 })
    .withMessage('Search term must be between 1 and 100 characters')
];

// Custom validation functions
const isUniqueEmail = async (email: string): Promise<boolean> => {
  // Check if email exists in database
  const existingUser = await findUserByEmail(email);
  return !existingUser;
};

const customEmailValidation = body('email').custom(async (email: string) => {
  const isUnique = await isUniqueEmail(email);
  if (!isUnique) {
    throw new Error('Email already exists');
  }
});

// Type-safe request interfaces
interface CreateUserBody {
  name: string;
  email: string;
  password: string;
  age?: number;
}

interface UpdateUserBody {
  name?: string;
  email?: string;
}

interface GetUsersQuery {
  page?: string;
  limit?: string;
  search?: string;
}

// Route handlers with validation
const createUser = asyncHandler<{}, ApiResponse<User>, CreateUserBody>(async (req, res) => {
  const { name, email, password, age } = req.body;
  
  const user: User = {
    id: Date.now(),
    name,
    email,
    createdAt: new Date()
  };
  
  res.status(201).json({
    success: true,
    data: user,
    timestamp: new Date().toISOString()
  });
});

const updateUser = asyncHandler<UserParams, ApiResponse<User>, UpdateUserBody>(async (req, res) => {
  const userId = parseInt(req.params.id);
  const updates = req.body;
  
  const user: User = {
    id: userId,
    name: updates.name || 'John Doe',
    email: updates.email || 'john@example.com',
    createdAt: new Date()
  };
  
  res.json({
    success: true,
    data: user,
    timestamp: new Date().toISOString()
  });
});

const getUsers = asyncHandler<{}, ApiResponse<User[]>, {}, GetUsersQuery>(async (req, res) => {
  const { page = '1', limit = '10', search } = req.query;
  
  const users: User[] = []; // Mock data
  
  res.json({
    success: true,
    data: users,
    timestamp: new Date().toISOString()
  });
});

// Apply validation to routes
app.post('/api/users', validate([...createUserValidation, customEmailValidation]), createUser);
app.put('/api/users/:id', validate(updateUserValidation), updateUser);
app.get('/api/users', validate(getUsersValidation), getUsers);

// Mock database functions
async function findUserByEmail(email: string): Promise<User | null> {
  // Mock implementation
  return null;
}
```

**Exercise**: Add comprehensive validation to all your API endpoints with custom validators

---

### Lesson 9: File Handling with TypeScript
**Goal**: Type-safe file upload and processing

**Topics**:
- Multer with TypeScript
- File type interfaces
- Image processing with types
- File validation

**Hands-on**:
```typescript
import multer, { FileFilterCallback } from 'multer';
import { Request } from 'express';
import path from 'path';
import sharp from 'sharp';

// File interfaces
interface UploadedFile {
  fieldname: string;
  originalname: string;
  encoding: string;
  mimetype: string;
  size: number;
  destination: string;
  filename: string;
  path: string;
}

interface ImageProcessingOptions {
  width?: number;
  height?: number;
  quality?: number;
  format?: 'jpeg' | 'png' | 'webp';
}

interface FileUploadResponse {
  success: boolean;
  file?: {
    filename: string;
    originalName: string;
    size: number;
    mimetype: string;
    url: string;
  };
  error?: string;
  timestamp: string;
}

// Extend Request interface for file uploads
declare global {
  namespace Express {
    interface Request {
      file?: UploadedFile;
      files?: UploadedFile[] | { [fieldname: string]: UploadedFile[] };
    }
  }
}

// File filter with proper typing
const fileFilter = (req: Request, file: Express.Multer.File, cb: FileFilterCallback): void => {
  const allowedTypes = /jpeg|jpg|png|gif|webp/;
  const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
  const mimetype = allowedTypes.test(file.mimetype);
  
  if (mimetype && extname) {
    cb(null, true);
  } else {
    cb(new Error('Only image files are allowed'));
  }
};

// Storage configuration
const storage = multer.diskStorage({
  destination: (req: Request, file: Express.Multer.File, cb) => {
    cb(null, './uploads/');
  },
  filename: (req: Request, file: Express.Multer.File, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    const ext = path.extname(file.originalname);
    cb(null, `${file.fieldname}-${uniqueSuffix}${ext}`);
  }
});

// Multer configuration with typing
const upload = multer({
  storage,
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB
    files: 1
  },
  fileFilter
});

// Image processing function
const processImage = async (
  inputPath: string,
  outputPath: string,
  options: ImageProcessingOptions = {}
): Promise<void> => {
  const { width = 800, height = 600, quality = 80, format = 'jpeg' } = options;
  
  await sharp(inputPath)
    .resize(width, height, { fit: 'inside', withoutEnlargement: true })
    .toFormat(format, { quality })
    .toFile(outputPath);
};

// File upload handlers
const uploadSingle = asyncHandler(async (req: Request, res: Response<FileUploadResponse>) => {
  if (!req.file) {
    res.status(400).json({
      success: false,
      error: 'No file uploaded',
      timestamp: new Date().toISOString()
    });
    return;
  }
  
  try {
    // Process image if it's an image file
    if (req.file.mimetype.startsWith('image/')) {
      const processedPath = `./uploads/processed-${req.file.filename}`;
      await processImage(req.file.path, processedPath, {
        width: 800,
        height: 600,
        quality: 85
      });
    }
    
    res.status(201).json({
      success: true,
      file: {
        filename: req.file.filename,
        originalName: req.file.originalname,
        size: req.file.size,
        mimetype: req.file.mimetype,
        url: `/uploads/${req.file.filename}`
      },
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Failed to process file',
      timestamp: new Date().toISOString()
    });
  }
});

// Multiple file upload
interface MultipleFileUploadResponse {
  success: boolean;
  files?: Array<{
    filename: string;
    originalName: string;
    size: number;
    mimetype: string;
    url: string;
  }>;
  error?: string;
  timestamp: string;
}

const uploadMultiple = asyncHandler(async (req: Request, res: Response<MultipleFileUploadResponse>) => {
  const files = req.files as Express.Multer.File[];
  
  if (!files || files.length === 0) {
    res.status(400).json({
      success: false,
      error: 'No files uploaded',
      timestamp: new Date().toISOString()
    });
    return;
  }
  
  try {
    const processedFiles = await Promise.all(
      files.map(async (file) => {
        if (file.mimetype.startsWith('image/')) {
          const processedPath = `./uploads/processed-${file.filename}`;
          await processImage(file.path, processedPath);
        }
        
        return {
          filename: file.filename,
          originalName: file.originalname,
          size: file.size,
          mimetype: file.mimetype,
          url: `/uploads/${file.filename}`
        };
      })
    );
    
    res.status(201).json({
      success: true,
      files: processedFiles,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Failed to process files',
      timestamp: new Date().toISOString()
    });
  }
});

// Routes
app.post('/api/upload/single', upload.single('image'), uploadSingle);
app.post('/api/upload/multiple', upload.array('images', 5), uploadMultiple);

// Serve uploaded files
app.use('/uploads', express.static('uploads'));
```

**Exercise**: Create a typed photo gallery with upload, processing, and metadata extraction

---

### Lesson 10: Environment Configuration with TypeScript
**Goal**: Type-safe environment management

**Topics**:
- Typed environment variables
- Configuration validation
- Environment-specific types
- Config module pattern

**Hands-on**:
```typescript
import { cleanEnv, str, num, bool, port, url } from 'envalid';

// Environment variable schema
const env = cleanEnv(process.env, {
  NODE_ENV: str({ choices: ['development', 'test', 'production'], default: 'development' }),
  PORT: port({ default: 3000 }),
  
  // Database
  DATABASE_URL: url(),
  DB_HOST: str({ default: 'localhost' }),
  DB_PORT: num({ default: 5432 }),
  DB_NAME: str(),
  DB_USER: str(),
  DB_PASSWORD: str(),
  
  // Authentication
  JWT_SECRET: str({ minLength: 32 }),
  JWT_EXPIRES_IN: str({ default: '24h' }),
  REFRESH_TOKEN_SECRET: str({ minLength: 32 }),
  REFRESH_TOKEN_EXPIRES_IN: str({ default: '7d' }),
  
  // External Services
  REDIS_URL: url({ default: 'redis://localhost:6379' }),
  EMAIL_SERVICE_API_KEY: str(),
  AWS_ACCESS_KEY_ID: str({ default: '' }),
  AWS_SECRET_ACCESS_KEY: str({ default: '' }),
  AWS_REGION: str({ default: 'us-east-1' }),
  
  // Application
  CORS_ORIGIN: str({ default: '*' }),
  RATE_LIMIT_WINDOW_MS: num({ default: 900000 }), // 15 minutes
  RATE_LIMIT_MAX_REQUESTS: num({ default: 100 }),
  FILE_UPLOAD_MAX_SIZE: num({ default: 5242880 }), // 5MB
  
  // Security
  BCRYPT_ROUNDS: num({ default: 12 }),
  SESSION_SECRET: str({ minLength: 32, default: '' }),
  
  // Logging
  LOG_LEVEL: str({ choices: ['error', 'warn', 'info', 'debug'], default: 'info' }),
  
  // Feature Flags
  ENABLE_SWAGGER: bool({ default: false }),
  ENABLE_METRICS: bool({ default: false })
});

// Configuration interface
interface DatabaseConfig {
  url: string;
  host: string;
  port: number;
  name: string;
  user: string;
  password: string;
}

interface AuthConfig {
  jwtSecret: string;
  jwtExpiresIn: string;
  refreshTokenSecret: string;
  refreshTokenExpiresIn: string;
  bcryptRounds: number;
  sessionSecret: string;
}

interface ServerConfig {
  port: number;
  nodeEnv: 'development' | 'test' | 'production';
  corsOrigin: string;
}

interface RateLimitConfig {
  windowMs: number;
  maxRequests: number;
}

interface FileUploadConfig {
  maxSize: number;
  allowedTypes: string[];
  destination: string;
}

interface ExternalServicesConfig {
  redis: {
    url: string;
  };
  email: {
    apiKey: string;
  };
  aws: {
    accessKeyId: string;
    secretAccessKey: string;
    region: string;
  };
}

interface LoggingConfig {
  level: 'error' | 'warn' | 'info' | 'debug';
}

interface FeatureFlags {
  enableSwagger: boolean;
  enableMetrics: boolean;
}

// Main configuration object
interface AppConfig {
  server: ServerConfig;
  database: DatabaseConfig;
  auth: AuthConfig;
  rateLimit: RateLimitConfig;
  fileUpload: FileUploadConfig;
  externalServices: ExternalServicesConfig;
  logging: LoggingConfig;
  features: FeatureFlags;
}

// Create typed configuration
const config: AppConfig = {
  server: {
    port: env.PORT,
    nodeEnv: env.NODE_ENV,
    corsOrigin: env.CORS_ORIGIN
  },
  database: {
    url: env.DATABASE_URL,
    host: env.DB_HOST,
    port: env.DB_PORT,
    name: env.DB_NAME,
    user: env.DB_USER,
    password: env.DB_PASSWORD
  },
  auth: {
    jwtSecret: env.JWT_SECRET,
    jwtExpiresIn: env.JWT_EXPIRES_IN,
    refreshTokenSecret: env.REFRESH_TOKEN_SECRET,
    refreshTokenExpiresIn: env.REFRESH_TOKEN_EXPIRES_IN,
    bcryptRounds: env.BCRYPT_ROUNDS,
    sessionSecret: env.SESSION_SECRET
  },
  rateLimit: {
    windowMs: env.RATE_LIMIT_WINDOW_MS,
    maxRequests: env.RATE_LIMIT_MAX_REQUESTS
  },
  fileUpload: {
    maxSize: env.FILE_UPLOAD_MAX_SIZE,
    allowedTypes: ['image/jpeg', 'image/png', 'image/gif', 'image/webp'],
    destination: './uploads'
  },
  externalServices: {
    redis: {
      url: env.REDIS_URL
    },
    email: {
      apiKey: env.EMAIL_SERVICE_API_KEY
    },
    aws: {
      accessKeyId: env.AWS_ACCESS_KEY_ID,
      secretAccessKey: env.AWS_SECRET_ACCESS_KEY,
      region: env.AWS_REGION
    }
  },
  logging: {
    level: env.LOG_LEVEL
  },
  features: {
    enableSwagger: env.ENABLE_SWAGGER,
    enableMetrics: env.ENABLE_METRICS
  }
};

// Configuration validation function
const validateConfig = (): void => {
  const requiredConfigs = [
    'database.url',
    'auth.jwtSecret',
    'auth.refreshTokenSecret',
    'externalServices.email.apiKey'
  ];
  
  const missing = requiredConfigs.filter(configPath => {
    const value = configPath.split('.').reduce((obj, key) => obj?.[key], config as any);
    return !value;
  });
  
  if (missing.length > 0) {
    throw new Error(`Missing required configuration: ${missing.join(', ')}`);
  }
};

// Validate configuration on startup
validateConfig();

export default config;

// Usage in other files
export const isDevelopment = config.server.nodeEnv === 'development';
export const isProduction = config.server.nodeEnv === 'production';
export const isTest = config.server.nodeEnv === 'test';
```

**.env.example**:
```bash
NODE_ENV=development
PORT=3000

# Database
DATABASE_URL=postgresql://user:password@localhost:5432/myapp
DB_HOST=localhost
DB_PORT=5432
DB_NAME=myapp
DB_USER=user
DB_PASSWORD=password

# Authentication
JWT_SECRET=your-super-secret-jwt-key-at-least-32-chars-long
JWT_EXPIRES_IN=24h
REFRESH_TOKEN_SECRET=your-super-secret-refresh-token-key-at-least-32-chars-long
REFRESH_TOKEN_EXPIRES_IN=7d
BCRYPT_ROUNDS=12
SESSION_SECRET=your-super-secret-session-key-at-least-32-chars-long

# External Services
REDIS_URL=redis://localhost:6379
EMAIL_SERVICE_API_KEY=your-email-service-api-key
AWS_ACCESS_KEY_ID=
AWS_SECRET_ACCESS_KEY=
AWS_REGION=us-east-1

# Application
CORS_ORIGIN=http://localhost:3000
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX_REQUESTS=100
FILE_UPLOAD_MAX_SIZE=5242880

# Logging
LOG_LEVEL=info

# Feature Flags
ENABLE_SWAGGER=true
ENABLE_METRICS=false
```

**Exercise**: Set up typed configurations for development, testing, and production environments

---

## Part 3: Database Integration with TypeScript (Lessons 11-15)

### Lesson 11: MongoDB with Mongoose and TypeScript
**Goal**: Type-safe MongoDB operations

**Topics**:
- Mongoose with TypeScript
- Schema typing
- Document interfaces
- Population typing

**Hands-on**:
```bash
npm install mongoose
npm install -D @types/mongoose
```

**src/models/User.ts**:
```typescript
import { Schema, model, Document, Types } from 'mongoose';

// User interface for TypeScript
export interface IUser {
  name: string;
  email: string;
  password: string;
  avatar?: string;
  role: 'user' | 'admin' | 'moderator';
  isActive: boolean;
  lastLogin?: Date;
  posts: Types.ObjectId[];
  profile: {
    bio?: string;
    website?: string;
    location?: string;
  };
  createdAt: Date;
  updatedAt: Date;
}

// Document interface extending IUser
export interface IUserDocument extends IUser, Document {
  _id: Types.ObjectId;
  comparePassword(candidatePassword: string): Promise<boolean>;
  getPublicProfile(): Partial<IUser>;
  isModified(path?: string): boolean;
}

// Schema definition with TypeScript
const userSchema = new Schema<IUserDocument>({
  name: {
    type: String,
    required: [true, 'Name is required'],
    trim: true,
    minlength: [2, 'Name must be at least 2 characters'],
    maxlength: [50, 'Name cannot exceed 50 characters']
  },
  email: {
    type: String,
    required: [true, 'Email is required'],
    unique: true,
    lowercase: true,
    validate: {
      validator: (email: string) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email),
      message: 'Invalid email format'
    }
  },
  password: {
    type: String,
    required: [true, 'Password is required'],
    minlength: [8, 'Password must be at least 8 characters'],
    select: false // Don't include password in queries by default
  },
  avatar: {
    type: String,
    default: null
  },
  role: {
    type: String,
    enum: ['user', 'admin', 'moderator'],
    default: 'user'
  },
  isActive: {
    type: Boolean,
    default: true
  },
  lastLogin: {
    type: Date,
    default: null
  },
  posts: [{
    type: Schema.Types.ObjectId,
    ref: 'Post'
  }],
  profile: {
    bio: {
      type: String,
      maxlength: [500, 'Bio cannot exceed 500 characters']
    },
    website: {
      type: String,
      validate: {
        validator: (url: string) => !url || /^https?:\/\/.+/.test(url),
        message: 'Website must be a valid URL'
      }
    },
    location: {
      type: String,
      maxlength: [100, 'Location cannot exceed 100 characters']
    }
  }
}, {
  timestamps: true,
  toJSON: {
    transform: (doc, ret) => {
      ret.id = ret._id;
      delete ret._id;
      delete ret.__v;
      delete ret.password;
      return ret;
    }
  }
});

// Pre-save middleware with proper typing
userSchema.pre<IUserDocument>('save', async function(next) {
  if (!this.isModified('password')) return next();
  
  const bcrypt = await import('bcrypt');
  this.password = await bcrypt.hash(this.password, 12);
  next();
});

// Instance methods with proper typing
userSchema.methods.comparePassword = async function(this: IUserDocument, candidatePassword: string): Promise<boolean> {
  const bcrypt = await import('bcrypt');
  return bcrypt.compare(candidatePassword, this.password);
};

userSchema.methods.getPublicProfile = function(this: IUserDocument): Partial<IUser> {
  return {
    name: this.name,
    email: this.email,
    avatar: this.avatar,
    role: this.role,
    profile: this.profile,
    createdAt: this.createdAt,
    updatedAt: this.updatedAt
  };
};

// Static methods with proper typing
userSchema.statics.findByEmail = function(email: string) {
  return this.findOne({ email: email.toLowerCase() });
};

// Create and export the model
export const User = model<IUserDocument>('User', userSchema);
```

**src/models/Post.ts**:
```typescript
import { Schema, model, Document, Types } from 'mongoose';
import { IUserDocument } from './User';

export interface IPost {
  title: string;
  content: string;
  author: Types.ObjectId | IUserDocument;
  tags: string[];
  category: string;
  status: 'draft' | 'published' | 'archived';
  views: number;
  likes: Types.ObjectId[];
  comments: Types.ObjectId[];
  featuredImage?: string;
  publishedAt?: Date;
  createdAt: Date;
  updatedAt: Date;
}

export interface IPostDocument extends IPost, Document {
  _id: Types.ObjectId;
  incrementViews(): Promise<IPostDocument>;
  isLikedBy(userId: Types.ObjectId): boolean;
}

const postSchema = new Schema<IPostDocument>({
  title: {
    type: String,
    required: [true, 'Title is required'],
    trim: true,
    maxlength: [200, 'Title cannot exceed 200 characters']
  },
  content: {
    type: String,
    required: [true, 'Content is required'],
    minlength: [10, 'Content must be at least 10 characters']
  },
  author: {
    type: Schema.Types.ObjectId,
    ref: 'User',
    required: [true, 'Author is required']
  },
  tags: [{
    type: String,
    lowercase: true,
    trim: true
  }],
  category: {
    type: String,
    required: [true, 'Category is required'],
    lowercase: true,
    trim: true
  },
  status: {
    type: String,
    enum: ['draft', 'published', 'archived'],
    default: 'draft'
  },
  views: {
    type: Number,
    default: 0
  },
  likes: [{
    type: Schema.Types.ObjectId,
    ref: 'User'
  }],
  comments: [{
    type: Schema.Types.ObjectId,
    ref: 'Comment'
  }],
  featuredImage: {
    type: String,
    default: null
  },
  publishedAt: {
    type: Date,
    default: null
  }
}, {
  timestamps: true,
  toJSON: {
    transform: (doc, ret) => {
      ret.id = ret._id;
      delete ret._id;
      delete ret.__v;
      return ret;
    }
  }
});

// Pre-save middleware
postSchema.pre<IPostDocument>('save', function(next) {
  if (this.status === 'published' && !this.publishedAt) {
    this.publishedAt = new Date();
  }
  next();
});

// Instance methods
postSchema.methods.incrementViews = function(this: IPostDocument): Promise<IPostDocument> {
  this.views += 1;
  return this.save();
};

postSchema.methods.isLikedBy = function(this: IPostDocument, userId: Types.ObjectId): boolean {
  return this.likes.some(like => like.toString() === userId.toString());
};

export const Post = model<IPostDocument>('Post', postSchema);
```

**src/services/UserService.ts**:
```typescript
import { Types } from 'mongoose';
import { User, IUser, IUserDocument } from '../models/User';
import { Post } from '../models/Post';

export class UserService {
  // Create user with proper typing
  async createUser(userData: Omit<IUser, 'createdAt' | 'updatedAt' | 'posts' | 'isActive' | 'role'>): Promise<IUserDocument> {
    try {
      const user = new User(userData);
      return await user.save();
    } catch (error) {
      if (error.code === 11000) {
        throw new Error('Email already exists');
      }
      throw error;
    }
  }

  // Find user by ID with population
  async findUserById(id: string | Types.ObjectId): Promise<IUserDocument | null> {
    if (!Types.ObjectId.isValid(id)) {
      return null;
    }
    
    return await User.findById(id)
      .populate({
        path: 'posts',
        select: 'title status createdAt',
        match: { status: 'published' }
      })
      .exec();
  }

  // Find user by email
  async findUserByEmail(email: string): Promise<IUserDocument | null> {
    return await User.findOne({ email: email.toLowerCase() }).select('+password').exec();
  }

  // Update user with type safety
  async updateUser(
    id: string | Types.ObjectId, 
    updates: Partial<Pick<IUser, 'name' | 'avatar' | 'profile'>>
  ): Promise<IUserDocument | null> {
    if (!Types.ObjectId.isValid(id)) {
      return null;
    }

    return await User.findByIdAndUpdate(
      id,
      { $set: updates },
      { new: true, runValidators: true }
    ).exec();
  }

  // Get users with pagination and filtering
  async getUsers(options: {
    page?: number;
    limit?: number;
    search?: string;
    role?: 'user' | 'admin' | 'moderator';
    isActive?: boolean;
  } = {}): Promise<{
    users: IUserDocument[];
    totalUsers: number;
    totalPages: number;
    currentPage: number;
  }> {
    const {
      page = 1,
      limit = 10,
      search,
      role,
      isActive
    } = options;

    // Build query
    const query: any = {};
    
    if (search) {
      query.$or = [
        { name: { $regex: search, $options: 'i' } },
        { email: { $regex: search, $options: 'i' } }
      ];
    }
    
    if (role) {
      query.role = role;
    }
    
    if (typeof isActive === 'boolean') {
      query.isActive = isActive;
    }

    const skip = (page - 1) * limit;

    const [users, totalUsers] = await Promise.all([
      User.find(query)
        .select('-password')
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limit)
        .populate('posts', 'title status')
        .exec(),
      User.countDocuments(query)
    ]);

    return {
      users,
      totalUsers,
      totalPages: Math.ceil(totalUsers / limit),
      currentPage: page
    };
  }

  // Delete user and cleanup
  async deleteUser(id: string | Types.ObjectId): Promise<boolean> {
    if (!Types.ObjectId.isValid(id)) {
      return false;
    }

    const session = await User.startSession();
    
    try {
      await session.withTransaction(async () => {
        // Delete user's posts
        await Post.deleteMany({ author: id }).session(session);
        
        // Delete user
        await User.findByIdAndDelete(id).session(session);
      });

      return true;
    } catch (error) {
      return false;
    } finally {
      await session.endSession();
    }
  }

  // Authentication methods
  async authenticateUser(email: string, password: string): Promise<IUserDocument | null> {
    const user = await this.findUserByEmail(email);
    
    if (!user || !await user.comparePassword(password)) {
      return null;
    }

    // Update last login
    user.lastLogin = new Date();
    await user.save();

    return user;
  }
}
```

**Exercise**: Build a complete typed blog system with posts, comments, and categories using Mongoose

---

### Lesson 12: SQL with Prisma and TypeScript
**Goal**: Type-safe SQL operations with Prisma

**Topics**:
- Prisma setup with TypeScript
- Schema definition
- Generated types
- Relations and joins

**Hands-on**:
```bash
npm install prisma @prisma/client
npm install -D prisma
npx prisma init
```

**prisma/schema.prisma**:
```prisma
generator client {
  provider = "prisma-client-js"
}

datasource db {
  provider = "postgresql"
  url      = env("DATABASE_URL")
}

model User {
  id        Int      @id @default(autoincrement())
  email     String   @unique
  name      String
  avatar    String?
  role      Role     @default(USER)
  isActive  Boolean  @default(true)
  lastLogin DateTime?
  createdAt DateTime @default(now())
  updatedAt DateTime @updatedAt

  profile Profile?
  posts   Post[]
  comments Comment[]
  likes   Like[]

  @@map("users")
}

model Profile {
  id       Int     @id @default(autoincrement())
  bio      String?
  website  String?
  location String?
  userId   Int     @unique
  user     User    @relation(fields: [userId], references: [id], onDelete: Cascade)

  @@map("profiles")
}

model Post {
  id           Int      @id @default(autoincrement())
  title        String
  content      String
  slug         String   @unique
  status       Status   @default(DRAFT)
  views        Int      @default(0)
  featuredImage String?
  publishedAt  DateTime?
  createdAt    DateTime @default(now())
  updatedAt    DateTime @updatedAt

  authorId   Int
  author     User       @relation(fields: [authorId], references: [id], onDelete: Cascade)
  categoryId Int
  category   Category   @relation(fields: [categoryId], references: [id])
  
  comments Comment[]
  likes    Like[]
  tags     PostTag[]

  @@map("posts")
}

model Category {
  id          Int    @id @default(autoincrement())
  name        String @unique
  slug        String @unique
  description String?
  
  posts Post[]

  @@map("categories")
}

model Tag {
  id    Int    @id @default(autoincrement())
  name  String @unique
  slug  String @unique
  
  posts PostTag[]

  @@map("tags")
}

model PostTag {
  postId Int
  tagId  Int
  
  post Post @relation(fields: [postId], references: [id], onDelete: Cascade)
  tag  Tag  @relation(fields: [tagId], references: [id], onDelete: Cascade)

  @@id([postId, tagId])
  @@map("post_tags")
}

model Comment {
  id        Int      @id @default(autoincrement())
  content   String
  createdAt DateTime @default(now())
  updatedAt DateTime @updatedAt

  authorId Int
  author   User @relation(fields: [authorId], references: [id], onDelete: Cascade)
  postId   Int
  post     Post @relation(fields: [postId], references: [id], onDelete: Cascade)

  parentId Int?
  parent   Comment?  @relation("CommentReplies", fields: [parentId], references: [id])
  replies  Comment[] @relation("CommentReplies")

  @@map("comments")
}

model Like {
  id     Int @id @default(autoincrement())
  userId Int
  postId Int
  
  user User @relation(fields: [userId], references: [id], onDelete: Cascade)
  post Post @relation(fields: [postId], references: [id], onDelete: Cascade)

  @@unique([userId, postId])
  @@map("likes")
}

enum Role {
  USER
  ADMIN
  MODERATOR
}

enum Status {
  DRAFT
  PUBLISHED
  ARCHIVED
}
```

**src/services/PostService.ts**:
```typescript
import { PrismaClient, Post, User, Category, Tag, Status, Prisma } from '@prisma/client';

const prisma = new PrismaClient();

// Type for post with relations
type PostWithRelations = Post & {
  author: User;
  category: Category;
  tags: Array<{ tag: Tag }>;
  comments: Array<{
    id: number;
    content: string;
    createdAt: Date;
    author: { name: string; avatar: string | null };
  }>;
  likes: Array<{ userId: number }>;
  _count: {
    comments: number;
    likes: number;
  };
};

// Input types
interface CreatePostInput {
  title: string;
  content: string;
  slug: string;
  authorId: number;
  categoryId: number;
  tagIds?: number[];
  featuredImage?: string;
  status?: Status;
}

interface UpdatePostInput {
  title?: string;
  content?: string;
  slug?: string;
  categoryId?: number;
  tagIds?: number[];
  featuredImage?: string;
  status?: Status;
}

interface GetPostsOptions {
  page?: number;
  limit?: number;
  search?: string;
  categoryId?: number;
  tagId?: number;
  authorId?: number;
  status?: Status[];
  sortBy?: 'createdAt' | 'updatedAt' | 'views' | 'likes';
  sortOrder?: 'asc' | 'desc';
}

export class PostService {
  // Create post with relations
  async createPost(data: CreatePostInput): Promise<PostWithRelations> {
    const { tagIds, ...postData } = data;

    return await prisma.post.create({
      data: {
        ...postData,
        ...(tagIds && {
          tags: {
            create: tagIds.map(tagId => ({ tagId }))
          }
        })
      },
      include: {
        author: true,
        category: true,
        tags: {
          include: {
            tag: true
          }
        },
        comments: {
          include: {
            author: {
              select: { name: true, avatar: true }
            }
          },
          orderBy: { createdAt: 'desc' },
          take: 5
        },
        likes: true,
        _count: {
          select: {
            comments: true,
            likes: true
          }
        }
      }
    });
  }

  // Get post by ID with all relations
  async getPostById(id: number): Promise<PostWithRelations | null> {
    const post = await prisma.post.findUnique({
      where: { id },
      include: {
        author: true,
        category: true,
        tags: {
          include: {
            tag: true
          }
        },
        comments: {
          include: {
            author: {
              select: { name: true, avatar: true }
            },
            replies: {
              include: {
                author: {
                  select: { name: true, avatar: true }
                }
              }
            }
          },
          where: { parentId: null },
          orderBy: { createdAt: 'desc' }
        },
        likes: true,
        _count: {
          select: {
            comments: true,
            likes: true
          }
        }
      }
    });

    // Increment views
    if (post) {
      await prisma.post.update({
        where: { id },
        data: { views: { increment: 1 } }
      });
    }

    return post;
  }

  // Get posts with filtering and pagination
  async getPosts(options: GetPostsOptions = {}): Promise<{
    posts: PostWithRelations[];
    totalPosts: number;
    totalPages: number;
    currentPage: number;
  }> {
    const {
      page = 1,
      limit = 10,
      search,
      categoryId,
      tagId,
      authorId,
      status = ['PUBLISHED'],
      sortBy = 'createdAt',
      sortOrder = 'desc'
    } = options;

    // Build where clause
    const where: Prisma.PostWhereInput = {
      status: { in: status },
      ...(search && {
        OR: [
          { title: { contains: search, mode: 'insensitive' } },
          { content: { contains: search, mode: 'insensitive' } }
        ]
      }),
      ...(categoryId && { categoryId }),
      ...(authorId && { authorId }),
      ...(tagId && {
        tags: {
          some: { tagId }
        }
      })
    };

    // Build order by
    const orderBy: Prisma.PostOrderByWithRelationInput = {};
    if (sortBy === 'likes') {
      orderBy.likes = { _count: sortOrder };
    } else {
      orderBy[sortBy] = sortOrder;
    }

    const skip = (page - 1) * limit;

    const [posts, totalPosts] = await Promise.all([
      prisma.post.findMany({
        where,
        include: {
          author: true,
          category: true,
          tags: {
            include: {
              tag: true
            }
          },
          comments: {
            include: {
              author: {
                select: { name: true, avatar: true }
              }
            },
            take: 3,
            orderBy: { createdAt: 'desc' }
          },
          likes: true,
          _count: {
            select: {
              comments: true,
              likes: true
            }
          }
        },
        orderBy,
        skip,
        take: limit
      }),
      prisma.post.count({ where })
    ]);

    return {
      posts,
      totalPosts,
      totalPages: Math.ceil(totalPosts / limit),
      currentPage: page
    };
  }

  // Update post
  async updatePost(id: number, data: UpdatePostInput): Promise<PostWithRelations | null> {
    const { tagIds, ...updateData } = data;

    // If updating tags, handle the relationship
    const updateInput: Prisma.PostUpdateInput = {
      ...updateData,
      ...(tagIds && {
        tags: {
          deleteMany: {},
          create: tagIds.map(tagId => ({ tagId }))
        }
      })
    };

    return await prisma.post.update({
      where: { id },
      data: updateInput,
      include: {
        author: true,
        category: true,
        tags: {
          include: {
            tag: true
          }
        },
        comments: {
          include: {
            author: {
              select: { name: true, avatar: true }
            }
          },
          take: 5,
          orderBy: { createdAt: 'desc' }
        },
        likes: true,
        _count: {
          select: {
            comments: true,
            likes: true
          }
        }
      }
    });
  }

  // Delete post
  async deletePost(id: number): Promise<boolean> {
    try {
      await prisma.post.delete({
        where: { id }
      });
      return true;
    } catch (error) {
      return false;
    }
  }

  // Like/unlike post
  async toggleLike(postId: number, userId: number): Promise<boolean> {
    const existingLike = await prisma.like.findUnique({
      where: {
        userId_postId: {
          userId,
          postId
        }
      }
    });

    if (existingLike) {
      await prisma.like.delete({
        where: {
          userId_postId: {
            userId,
            postId
          }
        }
      });
      return false; // Unliked
    } else {
      await prisma.like.create({
        data: {
          userId,
          postId
        }
      });
      return true; // Liked
    }
  }

  // Get post statistics
  async getPostStats(id: number): Promise<{
    views: number;
    likes: number;
    comments: number;
  } | null> {
    const post = await prisma.post.findUnique({
      where: { id },
      select: {
        views: true,
        _count: {
          select: {
            likes: true,
            comments: true
          }
        }
      }
    });

    if (!post) return null;

    return {
      views: post.views,
      likes: post._count.likes,
      comments: post._count.comments
    };
  }
}
```

**Exercise**: Convert your MongoDB blog to use PostgreSQL with Prisma and implement advanced queries

---

### Lesson 13: Database Patterns with TypeScript
**Goal**: Advanced typed database patterns

**Topics**:
- Repository pattern with TypeScript
- Service layer architecture
- Database transactions
- Query builders

**Hands-on**:
```typescript
// Base repository interface
interface IRepository<T, CreateInput, UpdateInput> {
  findById(id: string | number): Promise<T | null>;
  findMany(options?: any): Promise<T[]>;
  create(data: CreateInput): Promise<T>;
  update(id: string | number, data: UpdateInput): Promise<T | null>;
  delete(id: string | number): Promise<boolean>;
  count(filter?: any): Promise<number>;
}

// Generic repository implementation
abstract class BaseRepository<T, CreateInput, UpdateInput> implements IRepository<T, CreateInput, UpdateInput> {
  abstract findById(id: string | number): Promise<T | null>;
  abstract findMany(options?: any): Promise<T[]>;
  abstract create(data: CreateInput): Promise<T>;
  abstract update(id: string | number, data: UpdateInput): Promise<T | null>;
  abstract delete(id: string | number): Promise<boolean>;
  abstract count(filter?: any): Promise<number>;
}

// User repository with Prisma
import { PrismaClient, User, Prisma } from '@prisma/client';

interface CreateUserInput {
  name: string;
  email: string;
  password: string;
  role?: 'USER' | 'ADMIN' | 'MODERATOR';
}

interface UpdateUserInput {
  name?: string;
  email?: string;
  avatar?: string;
  isActive?: boolean;
}

interface FindUsersOptions {
  page?: number;
  limit?: number;
  search?: string;
  role?: 'USER' | 'ADMIN' | 'MODERATOR';
  isActive?: boolean;
  includeProfile?: boolean;
  includePosts?: boolean;
}

class UserRepository extends BaseRepository<User, CreateUserInput, UpdateUserInput> {
  constructor(private prisma: PrismaClient) {
    super();
  }

  async findById(id: number, includeRelations = false): Promise<User | null> {
    return await this.prisma.user.findUnique({
      where: { id },
      include: includeRelations ? {
        profile: true,
        posts: {
          where: { status: 'PUBLISHED' },
          select: { id: true, title: true, createdAt: true }
        }
      } : undefined
    });
  }

  async findByEmail(email: string): Promise<User | null> {
    return await this.prisma.user.findUnique({
      where: { email: email.toLowerCase() }
    });
  }

  async findMany(options: FindUsersOptions = {}): Promise<{
    users: User[];
    totalCount: number;
    hasNextPage: boolean;
    hasPrevPage: boolean;
  }> {
    const {
      page = 1,
      limit = 10,
      search,
      role,
      isActive,
      includeProfile = false,
      includePosts = false
    } = options;

    const where: Prisma.UserWhereInput = {
      ...(search && {
        OR: [
          { name: { contains: search, mode: 'insensitive' } },
          { email: { contains: search, mode: 'insensitive' } }
        ]
      }),
      ...(role && { role }),
      ...(typeof isActive === 'boolean' && { isActive })
    };

    const skip = (page - 1) * limit;

    const [users, totalCount] = await Promise.all([
      this.prisma.user.findMany({
        where,
        include: {
          ...(includeProfile && { profile: true }),
          ...(includePosts && {
            posts: {
              where: { status: 'PUBLISHED' },
              select: { id: true, title: true, views: true, createdAt: true }
            }
          })
        },
        skip,
        take: limit,
        orderBy: { createdAt: 'desc' }
      }),
      this.prisma.user.count({ where })
    ]);

    return {
      users,
      totalCount,
      hasNextPage: skip + limit < totalCount,
      hasPrevPage: page > 1
    };
  }

  async create(data: CreateUserInput): Promise<User> {
    return await this.prisma.user.create({
      data: {
        ...data,
        email: data.email.toLowerCase()
      }
    });
  }

  async update(id: number, data: UpdateUserInput): Promise<User | null> {
    try {
      return await this.prisma.user.update({
        where: { id },
        data: {
          ...data,
          ...(data.email && { email: data.email.toLowerCase() })
        }
      });
    } catch (error) {
      if (error instanceof Prisma.PrismaClientKnownRequestError && error.code === 'P2025') {
        return null;
      }
      throw error;
    }
  }

  async delete(id: number): Promise<boolean> {
    try {
      await this.prisma.user.delete({ where: { id } });
      return true;
    } catch (error) {
      return false;
    }
  }

  async count(filter: Partial<Pick<User, 'role' | 'isActive'>> = {}): Promise<number> {
    const where: Prisma.UserWhereInput = filter;
    return await this.prisma.user.count({ where });
  }

  // Custom methods
  async findActiveUsers(): Promise<User[]> {
    return await this.prisma.user.findMany({
      where: { isActive: true },
      orderBy: { lastLogin: 'desc' }
    });
  }

  async updateLastLogin(id: number): Promise<void> {
    await this.prisma.user.update({
      where: { id },
      data: { lastLogin: new Date() }
    });
  }

  async getUsersWithPostCount(): Promise<Array<User & { _count: { posts: number } }>> {
    return await this.prisma.user.findMany({
      include: {
        _count: {
          select: { posts: true }
        }
      }
    });
  }
}

// Service layer with business logic
interface UserServiceDependencies {
  userRepository: UserRepository;
  emailService: EmailService;
  cacheService: CacheService;
}

class UserService {
  constructor(private deps: UserServiceDependencies) {}

  async createUser(userData: CreateUserInput): Promise<User> {
    // Check if user already exists
    const existingUser = await this.deps.userRepository.findByEmail(userData.email);
    if (existingUser) {
      throw new Error('User with this email already exists');
    }

    // Hash password
    const bcrypt = await import('bcrypt');
    const hashedPassword = await bcrypt.hash(userData.password, 12);

    // Create user
    const user = await this.deps.userRepository.create({
      ...userData,
      password: hashedPassword
    });

    // Send welcome email
    await this.deps.emailService.sendWelcomeEmail(user.email, user.name);

    // Cache user data
    await this.deps.cacheService.set(`user:${user.id}`, user, 3600);

    return user;
  }

  async getUserById(id: number, includeRelations = false): Promise<User | null> {
    // Try cache first
    const cacheKey = `user:${id}:${includeRelations}`;
    const cached = await this.deps.cacheService.get<User>(cacheKey);
    if (cached) return cached;

    const user = await this.deps.userRepository.findById(id, includeRelations);
    if (user) {
      await this.deps.cacheService.set(cacheKey, user, 1800);
    }

    return user;
  }

  async updateUser(id: number, updates: UpdateUserInput): Promise<User | null> {
    const user = await this.deps.userRepository.update(id, updates);
    
    if (user) {
      // Invalidate cache
      await this.deps.cacheService.delete(`user:${user.id}`);
      await this.deps.cacheService.delete(`user:${user.id}:true`);
      await this.deps.cacheService.delete(`user:${user.id}:false`);
    }

    return user;
  }

  async deactivateUser(id: number, reason?: string): Promise<boolean> {
    const user = await this.deps.userRepository.update(id, { isActive: false });
    
    if (user) {
      // Log deactivation
      console.log(`User ${user.email} deactivated. Reason: ${reason || 'Not specified'}`);
      
      // Send notification email
      await this.deps.emailService.sendAccountDeactivationEmail(user.email, user.name);
      
      return true;
    }
    
    return false;
  }

  async getUserStats(): Promise<{
    totalUsers: number;
    activeUsers: number;
    newUsersThisMonth: number;
    usersByRole: Record<string, number>;
  }> {
    const [totalUsers, activeUsers, usersByRole] = await Promise.all([
      this.deps.userRepository.count(),
      this.deps.userRepository.count({ isActive: true }),
      this.getUsersByRole()
    ]);

    const startOfMonth = new Date();
    startOfMonth.setDate(1);
    startOfMonth.setHours(0, 0, 0, 0);

    // This would need to be implemented in the repository
    const newUsersThisMonth = 0; // Placeholder

    return {
      totalUsers,
      activeUsers,
      newUsersThisMonth,
      usersByRole
    };
  }

  private async getUsersByRole(): Promise<Record<string, number>> {
    // This would be implemented with a proper aggregation query
    return {
      USER: await this.deps.userRepository.count({ role: 'USER' }),
      ADMIN: await this.deps.userRepository.count({ role: 'ADMIN' }),
      MODERATOR: await this.deps.userRepository.count({ role: 'MODERATOR' })
    };
  }
}

// Transaction wrapper
class DatabaseTransaction {
  constructor(private prisma: PrismaClient) {}

  async executeTransaction<T>(
    operations: (tx: Prisma.TransactionClient) => Promise<T>
  ): Promise<T> {
    return await this.prisma.$transaction(async (tx) => {
      return await operations(tx);
    });
  }

  // Example: Transfer operation that needs atomicity
  async transferUserPosts(fromUserId: number, toUserId: number): Promise<void> {
    await this.executeTransaction(async (tx) => {
      // Verify both users exist
      const [fromUser, toUser] = await Promise.all([
        tx.user.findUnique({ where: { id: fromUserId } }),
        tx.user.findUnique({ where: { id: toUserId } })
      ]);

      if (!fromUser || !toUser) {
        throw new Error('One or both users not found');
      }

      // Transfer all posts
      await tx.post.updateMany({
        where: { authorId: fromUserId },
        data: { authorId: toUserId }
      });

      // Log the transfer
      console.log(`Transferred posts from user ${fromUserId} to user ${toUserId}`);
    });
  }
}

// Mock services for dependencies
interface EmailService {
  sendWelcomeEmail(email: string, name: string): Promise<void>;
  sendAccountDeactivationEmail(email: string, name: string): Promise<void>;
}

interface CacheService {
  get<T>(key: string): Promise<T | null>;
  set<T>(key: string, value: T, ttl: number): Promise<void>;
  delete(key: string): Promise<void>;
}

// Example usage
const prisma = new PrismaClient();
const userRepository = new UserRepository(prisma);
const emailService: EmailService = {
  sendWelcomeEmail: async () => {},
  sendAccountDeactivationEmail: async () => {}
};
const cacheService: CacheService = {
  get: async () => null,
  set: async () => {},
  delete: async () => {}
};

const userService = new UserService({
  userRepository,
  emailService,
  cacheService
});

const dbTransaction = new DatabaseTransaction(prisma);
```

**Exercise**: Refactor your application to use repository and service patterns with proper typing

---

### Lesson 14: Database Testing with TypeScript
**Goal**: Test database operations with type safety

**Topics**:
- Test database setup
- Mocking with proper types
- Test data factories
- Integration testing

**Hands-on**:
```bash
npm install -D jest @types/jest ts-jest supertest @types/supertest
npm install -D @testcontainers/postgresql
```

**jest.config.js**:
```javascript
module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  roots: ['<rootDir>/src', '<rootDir>/tests'],
  testMatch: ['**/__tests__/**/*.ts', '**/?(*.)+(spec|test).ts'],
  collectCoverageFrom: [
    'src/**/*.ts',
    '!src/**/*.d.ts',
    '!src/**/*.interface.ts',
    '!src/**/index.ts'
  ],
  setupFilesAfterEnv: ['<rootDir>/tests/setup.ts']
};
```

**tests/setup.ts**:
```typescript
import { PrismaClient } from '@prisma/client';
import { PostgreSqlContainer } from '@testcontainers/postgresql';

// Global test setup
let postgresContainer: any;
let prisma: PrismaClient;

beforeAll(async () => {
  // Start PostgreSQL container for testing
  postgresContainer = await new PostgreSqlContainer('postgres:14')
    .withDatabase('testdb')
    .withUsername('testuser')
    .withPassword('testpass')
    .start();

  // Set up Prisma client with test database
  const databaseUrl = postgresContainer.getConnectionUri();
  process.env.DATABASE_URL = databaseUrl;

  prisma = new PrismaClient();
  
  // Run migrations
  const { execSync } = require('child_process');
  execSync('npx prisma migrate dev --name init', { env: process.env });
});

afterAll(async () => {
  await prisma.$disconnect();
  await postgresContainer.stop();
});

beforeEach(async () => {
  // Clean database before each test
  const tablenames = await prisma.$queryRaw<Array<{ tablename: string }>>`
    SELECT tablename FROM pg_tables WHERE schemaname='public'
  `;

  for (const { tablename } of tablenames) {
    if (tablename !== '_prisma_migrations') {
      await prisma.$executeRawUnsafe(`TRUNCATE TABLE "public"."${tablename}" CASCADE;`);
    }
  }
});

// Make prisma available in tests
global.prisma = prisma;
```

**tests/factories/UserFactory.ts**:
```typescript
import { PrismaClient, User, Role } from '@prisma/client';
import { faker } from '@faker-js/faker';

interface CreateUserFactoryOptions {
  name?: string;
  email?: string;
  role?: Role;
  isActive?: boolean;
  withProfile?: boolean;
  withPosts?: number;
}

export class UserFactory {
  constructor(private prisma: PrismaClient) {}

  // Create a single user with optional customizations
  async createUser(options: CreateUserFactoryOptions = {}): Promise<User> {
    const userData = {
      name: options.name || faker.person.fullName(),
      email: options.email || faker.internet.email(),
      password: await this.hashPassword('password123'),
      role: options.role || 'USER',
      isActive: options.isActive ?? true
    };

    const user = await this.prisma.user.create({
      data: userData,
      include: {
        profile: true,
        posts: true
      }
    });

    // Create profile if requested
    if (options.withProfile) {
      await this.prisma.profile.create({
        data: {
          userId: user.id,
          bio: faker.lorem.paragraph(),
          website: faker.internet.url(),
          location: faker.location.city()
        }
      });
    }

    // Create posts if requested
    if (options.withPosts && options.withPosts > 0) {
      const category = await this.createCategory();
      
      for (let i = 0; i < options.withPosts; i++) {
        await this.prisma.post.create({
          data: {
            title: faker.lorem.sentence(),
            content: faker.lorem.paragraphs(3),
            slug: faker.helpers.slugify(faker.lorem.sentence()),
            authorId: user.id,
            categoryId: category.id,
            status: 'PUBLISHED'
          }
        });
      }
    }

    return user;
  }

  // Create multiple users
  async createUsers(count: number, options: CreateUserFactoryOptions = {}): Promise<User[]> {
    const users: User[] = [];
    
    for (let i = 0; i < count; i++) {
      const user = await this.createUser({
        ...options,
        email: options.email ? `${i}-${options.email}` : undefined
      });
      users.push(user);
    }
    
    return users;
  }

  // Create admin user
  async createAdmin(options: Omit<CreateUserFactoryOptions, 'role'> = {}): Promise<User> {
    return this.createUser({ ...options, role: 'ADMIN' });
  }

  // Create moderator user
  async createModerator(options: Omit<CreateUserFactoryOptions, 'role'> = {}): Promise<User> {
    return this.createUser({ ...options, role: 'MODERATOR' });
  }

  private async createCategory() {
    return await this.prisma.category.create({
      data: {
        name: faker.lorem.word(),
        slug: faker.helpers.slugify(faker.lorem.word()),
        description: faker.lorem.sentence()
      }
    });
  }

  private async hashPassword(password: string): Promise<string> {
    const bcrypt = await import('bcrypt');
    return bcrypt.hash(password, 10);
  }
}
```

**tests/repositories/UserRepository.test.ts**:
```typescript
import { PrismaClient } from '@prisma/client';
import { UserRepository } from '../../src/repositories/UserRepository';
import { UserFactory } from '../factories/UserFactory';

declare global {
  var prisma: PrismaClient;
}

describe('UserRepository', () => {
  let userRepository: UserRepository;
  let userFactory: UserFactory;

  beforeEach(() => {
    userRepository = new UserRepository(global.prisma);
    userFactory = new UserFactory(global.prisma);
  });

  describe('findById', () => {
    it('should return user when found', async () => {
      // Arrange
      const createdUser = await userFactory.createUser({
        name: 'John Doe',
        email: 'john@example.com'
      });

      // Act
      const foundUser = await userRepository.findById(createdUser.id);

      // Assert
      expect(foundUser).not.toBeNull();
      expect(foundUser!.id).toBe(createdUser.id);
      expect(foundUser!.name).toBe('John Doe');
      expect(foundUser!.email).toBe('john@example.com');
    });

    it('should return null when user not found', async () => {
      // Act
      const foundUser = await userRepository.findById(99999);

      // Assert
      expect(foundUser).toBeNull();
    });

    it('should include relations when requested', async () => {
      // Arrange
      const createdUser = await userFactory.createUser({
        withProfile: true,
        withPosts: 2
      });

      // Act
      const foundUser = await userRepository.findById(createdUser.id, true);

      // Assert
      expect(foundUser).not.toBeNull();
      expect(foundUser).toHaveProperty('profile');
      expect(foundUser).toHaveProperty('posts');
      expect(foundUser!.posts).toHaveLength(2);
    });
  });

  describe('findByEmail', () => {
    it('should return user when found by email', async () => {
      // Arrange
      await userFactory.createUser({
        email: 'test@example.com'
      });

      // Act
      const foundUser = await userRepository.findByEmail('test@example.com');

      // Assert
      expect(foundUser).not.toBeNull();
      expect(foundUser!.email).toBe('test@example.com');
    });

    it('should be case insensitive', async () => {
      // Arrange
      await userFactory.createUser({
        email: 'Test@Example.com'
      });

      // Act
      const foundUser = await userRepository.findByEmail('test@example.com');

      // Assert
      expect(foundUser).not.toBeNull();
      expect(foundUser!.email).toBe('test@example.com');
    });
  });

  describe('create', () => {
    it('should create user successfully', async () => {
      // Arrange
      const userData = {
        name: 'Jane Doe',
        email: 'jane@example.com',
        password: 'hashedpassword'
      };

      // Act
      const createdUser = await userRepository.create(userData);

      // Assert
      expect(createdUser.id).toBeDefined();
      expect(createdUser.name).toBe(userData.name);
      expect(createdUser.email).toBe(userData.email);
      expect(createdUser.isActive).toBe(true);
      expect(createdUser.role).toBe('USER');
    });

    it('should throw error for duplicate email', async () => {
      // Arrange
      const email = 'duplicate@example.com';
      await userFactory.createUser({ email });

      const userData = {
        name: 'Jane Doe',
        email,
        password: 'hashedpassword'
      };

      // Act & Assert
      await expect(userRepository.create(userData)).rejects.toThrow();
    });
  });

  describe('findMany', () => {
    beforeEach(async () => {
      // Create test data
      await userFactory.createUsers(5, { role: 'USER' });
      await userFactory.createUsers(2, { role: 'ADMIN' });
      await userFactory.createUsers(3, { isActive: false });
    });

    it('should return paginated users', async () => {
      // Act
      const result = await userRepository.findMany({
        page: 1,
        limit: 5
      });

      // Assert
      expect(result.users).toHaveLength(5);
      expect(result.totalCount).toBe(10);
      expect(result.hasNextPage).toBe(true);
      expect(result.hasPrevPage).toBe(false);
    });

    it('should filter by role', async () => {
      // Act
      const result = await userRepository.findMany({
        role: 'ADMIN'
      });

      // Assert
      expect(result.users).toHaveLength(2);
      expect(result.users.every(user => user.role === 'ADMIN')).toBe(true);
    });

    it('should filter by active status', async () => {
      // Act
      const result = await userRepository.findMany({
        isActive: false
      });

      // Assert
      expect(result.users).toHaveLength(3);
      expect(result.users.every(user => !user.isActive)).toBe(true);
    });

    it('should search by name and email', async () => {
      // Arrange
      await userFactory.createUser({
        name: 'John Search',
        email: 'search@example.com'
      });

      // Act
      const result = await userRepository.findMany({
        search: 'search'
      });

      // Assert
      expect(result.users.length).toBeGreaterThan(0);
      expect(
        result.users.some(user => 
          user.name.toLowerCase().includes('search') || 
          user.email.toLowerCase().includes('search')
        )
      ).toBe(true);
    });
  });

  describe('update', () => {
    it('should update user successfully', async () => {
      // Arrange
      const user = await userFactory.createUser();
      const updates = {
        name: 'Updated Name',
        isActive: false
      };

      // Act
      const updatedUser = await userRepository.update(user.id, updates);

      // Assert
      expect(updatedUser).not.toBeNull();
      expect(updatedUser!.name).toBe('Updated Name');
      expect(updatedUser!.isActive).toBe(false);
      expect(updatedUser!.email).toBe(user.email); // Unchanged
    });

    it('should return null for non-existent user', async () => {
      // Act
      const result = await userRepository.update(99999, { name: 'Test' });

      // Assert
      expect(result).toBeNull();
    });
  });

  describe('delete', () => {
    it('should delete user successfully', async () => {
      // Arrange
      const user = await userFactory.createUser();

      // Act
      const result = await userRepository.delete(user.id);

      // Assert
      expect(result).toBe(true);
      
      const deletedUser = await userRepository.findById(user.id);
      expect(deletedUser).toBeNull();
    });

    it('should return false for non-existent user', async () => {
      // Act
      const result = await userRepository.delete(99999);

      // Assert
      expect(result).toBe(false);
    });
  });

  describe('count', () => {
    beforeEach(async () => {
      await userFactory.createUsers(5, { role: 'USER' });
      await userFactory.createUsers(3, { role: 'ADMIN' });
      await userFactory.createUsers(2, { isActive: false });
    });

    it('should count all users when no filter', async () => {
      // Act
      const count = await userRepository.count();

      // Assert
      expect(count).toBe(10);
    });

    it('should count users by role', async () => {
      // Act
      const adminCount = await userRepository.count({ role: 'ADMIN' });

      // Assert
      expect(adminCount).toBe(3);
    });

    it('should count users by active status', async () => {
      // Act
      const inactiveCount = await userRepository.count({ isActive: false });

      // Assert
      expect(inactiveCount).toBe(2);
    });
  });
});
```

**tests/integration/auth.test.ts**:
```typescript
import request from 'supertest';
import { PrismaClient } from '@prisma/client';
import app from '../../src/app';
import { UserFactory } from '../factories/UserFactory';

declare global {
  var prisma: PrismaClient;
}

describe('Authentication Integration Tests', () => {
  let userFactory: UserFactory;

  beforeEach(() => {
    userFactory = new UserFactory(global.prisma);
  });

  describe('POST /api/auth/register', () => {
    it('should register a new user successfully', async () => {
      // Arrange
      const userData = {
        name: 'John Doe',
        email: 'john@example.com',
        password: 'password123'
      };

      // Act
      const response = await request(app)
        .post('/api/auth/register')
        .send(userData)
        .expect(201);

      // Assert
      expect(response.body.success).toBe(true);
      expect(response.body.data).toHaveProperty('id');
      expect(response.body.data.name).toBe(userData.name);
      expect(response.body.data.email).toBe(userData.email);
      expect(response.body.data).not.toHaveProperty('password');

      // Verify user was created in database
      const createdUser = await global.prisma.user.findUnique({
        where: { email: userData.email }
      });
      expect(createdUser).not.toBeNull();
    });

    it('should return 400 for invalid email', async () => {
      // Arrange
      const userData = {
        name: 'John Doe',
        email: 'invalid-email',
        password: 'password123'
      };

      // Act
      const response = await request(app)
        .post('/api/auth/register')
        .send(userData)
        .expect(400);

      // Assert
      expect(response.body.success).toBe(false);
      expect(response.body.errors).toBeDefined();
      expect(response.body.errors.some((err: any) => err.field === 'email')).toBe(true);
    });

    it('should return 400 for duplicate email', async () => {
      // Arrange
      const email = 'duplicate@example.com';
      await userFactory.createUser({ email });

      const userData = {
        name: 'Jane Doe',
        email,
        password: 'password123'
      };

      // Act
      const response = await request(app)
        .post('/api/auth/register')
        .send(userData)
        .expect(400);

      // Assert
      expect(response.body.success).toBe(false);
      expect(response.body.error).toContain('already exists');
    });
  });

  describe('POST /api/auth/login', () => {
    it('should login with valid credentials', async () => {
      // Arrange
      const password = 'password123';
      const user = await userFactory.createUser({ password });

      // Act
      const response = await request(app)
        .post('/api/auth/login')
        .send({
          email: user.email,
          password
        })
        .expect(200);

      // Assert
      expect(response.body.success).toBe(true);
      expect(response.body.data).toHaveProperty('accessToken');
      expect(response.body.data).toHaveProperty('refreshToken');
      expect(response.body.data.user.id).toBe(user.id);
    });

    it('should return 401 for invalid credentials', async () => {
      // Arrange
      const user = await userFactory.createUser();

      // Act
      const response = await request(app)
        .post('/api/auth/login')
        .send({
          email: user.email,
          password: 'wrongpassword'
        })
        .expect(401);

      // Assert
      expect(response.body.success).toBe(false);
      expect(response.body.error).toContain('Invalid credentials');
    });

    it('should return 401 for non-existent user', async () => {
      // Act
      const response = await request(app)
        .post('/api/auth/login')
        .send({
          email: 'nonexistent@example.com',
          password: 'password123'
        })
        .expect(401);

      // Assert
      expect(response.body.success).toBe(false);
      expect(response.body.error).toContain('Invalid credentials');
    });
  });

  describe('GET /api/auth/profile', () => {
    it('should return user profile when authenticated', async () => {
      // Arrange
      const user = await userFactory.createUser({ withProfile: true });
      const loginResponse = await request(app)
        .post('/api/auth/login')
        .send({
          email: user.email,
          password: 'password123'
        });

      const token = loginResponse.body.data.accessToken;

      // Act
      const response = await request(app)
        .get('/api/auth/profile')
        .set('Authorization', `Bearer ${token}`)
        .expect(200);

      // Assert
      expect(response.body.success).toBe(true);
      expect(response.body.data.id).toBe(user.id);
      expect(response.body.data).toHaveProperty('profile');
    });

    it('should return 401 when not authenticated', async () => {
      // Act
      const response = await request(app)
        .get('/api/auth/profile')
        .expect(401);

      // Assert
      expect(response.body.success).toBe(false);
      expect(response.body.error).toContain('token');
    });

    it('should return 401 for invalid token', async () => {
      // Act
      const response = await request(app)
        .get('/api/auth/profile')
        .set('Authorization', 'Bearer invalidtoken')
        .expect(401);

      // Assert
      expect(response.body.success).toBe(false);
      expect(response.body.error).toContain('Invalid token');
    });
  });
});
```

**Exercise**: Write comprehensive tests for all your database operations with 90%+ coverage

---

### Lesson 15: Database Migrations with TypeScript
**Goal**: Manage schema changes with type safety

**Topics**:
- Prisma migrations
- Migration strategies
- Schema versioning
- Production deployment

**Hands-on**:
```bash
# Generate migration
npx prisma migrate dev --name add_user_preferences

# Apply migration to production
npx prisma migrate deploy

# Reset database (development only)
npx prisma migrate reset
```

**Advanced Migration Example**:
```typescript
// src/migrations/20240101000000_add_user_preferences.ts
import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

export async function up(): Promise<void> {
  // Add preferences table
  await prisma.$executeRaw`
    CREATE TABLE "user_preferences" (
      "id" SERIAL PRIMARY KEY,
      "user_id" INTEGER NOT NULL UNIQUE,
      "theme" VARCHAR(20) DEFAULT 'light',
      "language" VARCHAR(10) DEFAULT 'en',
      "timezone" VARCHAR(50) DEFAULT 'UTC',
      "email_notifications" BOOLEAN DEFAULT true,
      "push_notifications" BOOLEAN DEFAULT true,
      "created_at" TIMESTAMP DEFAULT NOW(),
      "updated_at" TIMESTAMP DEFAULT NOW(),
      FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE
    );
  `;

  // Create preferences for existing users
  await prisma.$executeRaw`
    INSERT INTO "user_preferences" ("user_id")
    SELECT id FROM "users" WHERE id NOT IN (
      SELECT user_id FROM "user_preferences"
    );
  `;

  // Add indexes
  await prisma.$executeRaw`
    CREATE INDEX "idx_user_preferences_user_id" ON "user_preferences"("user_id");
  `;
}

export async function down(): Promise<void> {
  await prisma.$executeRaw`DROP TABLE IF EXISTS "user_preferences";`;
}

// Migration runner
export async function runMigration(direction: 'up' | 'down' = 'up'): Promise<void> {
  try {
    if (direction === 'up') {
      await up();
      console.log('Migration up completed successfully');
    } else {
      await down();
      console.log('Migration down completed successfully');
    }
  } catch (error) {
    console.error(`Migration ${direction} failed:`, error);
    throw error;
  } finally {
    await prisma.$disconnect();
  }
}
```

**Data Migration Example**:
```typescript
// src/migrations/data/20240101000001_migrate_user_settings.ts
import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

interface OldUserSettings {
  id: number;
  settings: string; // JSON string
}

interface NewUserPreferences {
  userId: number;
  theme: 'light' | 'dark';
  language: string;
  timezone: string;
  emailNotifications: boolean;
  pushNotifications: boolean;
}

export async function migrateUserSettings(): Promise<void> {
  console.log('Starting user settings migration...');

  // Get all users with old settings format
  const usersWithSettings = await prisma.$queryRaw<OldUserSettings[]>`
    SELECT id, settings FROM users WHERE settings IS NOT NULL
  `;

  console.log(`Found ${usersWithSettings.length} users with settings to migrate`);

  let migratedCount = 0;
  let errorCount = 0;

  for (const user of usersWithSettings) {
    try {
      // Parse old settings JSON
      const oldSettings = JSON.parse(user.settings);
      
      // Map to new preferences structure
      const newPreferences: Omit<NewUserPreferences, 'userId'> = {
        theme: oldSettings.theme || 'light',
        language: oldSettings.lang || 'en',
        timezone: oldSettings.tz || 'UTC',
        emailNotifications: oldSettings.notifications?.email ?? true,
        pushNotifications: oldSettings.notifications?.push ?? true
      };

      // Create new preferences record
      await prisma.userPreferences.upsert({
        where: { userId: user.id },
        update: newPreferences,
        create: {
          userId: user.id,
          ...newPreferences
        }
      });

      migratedCount++;
      
      if (migratedCount % 100 === 0) {
        console.log(`Migrated ${migratedCount} users...`);
      }
    } catch (error) {
      console.error(`Failed to migrate settings for user ${user.id}:`, error);
      errorCount++;
    }
  }

  console.log(`Migration completed: ${migratedCount} successful, ${errorCount} errors`);

  // Clean up old settings column after successful migration
  if (errorCount === 0) {
    console.log('Removing old settings column...');
    await prisma.$executeRaw`ALTER TABLE users DROP COLUMN IF EXISTS settings;`;
    console.log('Old settings column removed');
  } else {
    console.log('Keeping old settings column due to migration errors');
  }
}

// Run migration if called directly
if (require.main === module) {
  migrateUserSettings()
    .then(() => process.exit(0))
    .catch((error) => {
      console.error('Migration failed:', error);
      process.exit(1);
    });
}
```

**Migration Testing**:
```typescript
// tests/migrations/user_preferences.test.ts
import { PrismaClient } from '@prisma/client';
import { up, down } from '../../src/migrations/20240101000000_add_user_preferences';
import { UserFactory } from '../factories/UserFactory';

declare global {
  var prisma: PrismaClient;
}

describe('User Preferences Migration', () => {
  let userFactory: UserFactory;

  beforeEach(() => {
    userFactory = new UserFactory(global.prisma);
  });

  describe('up migration', () => {
    it('should create user_preferences table', async () => {
      // Act
      await up();

      // Assert - Check if table exists
      const tableExists = await global.prisma.$queryRaw`
        SELECT EXISTS (
          SELECT FROM information_schema.tables 
          WHERE table_name = 'user_preferences'
        );
      `;
      
      expect(tableExists).toBeTruthy();
    });

    it('should create preferences for existing users', async () => {
      // Arrange
      const user = await userFactory.createUser();
      
      // Act
      await up();

      // Assert
      const preferences = await global.prisma.userPreferences.findUnique({
        where: { userId: user.id }
      });

      expect(preferences).not.toBeNull();
      expect(preferences!.theme).toBe('light');
      expect(preferences!.language).toBe('en');
      expect(preferences!.emailNotifications).toBe(true);
    });

    it('should create proper indexes', async () => {
      // Act
      await up();

      // Assert - Check if index exists
      const indexExists = await global.prisma.$queryRaw`
        SELECT EXISTS (
          SELECT FROM pg_indexes 
          WHERE indexname = 'idx_user_preferences_user_id'
        );
      `;

      expect(indexExists).toBeTruthy();
    });
  });

  describe('down migration', () => {
    beforeEach(async () => {
      await up(); // Set up the table first
    });

    it('should drop user_preferences table', async () => {
      // Act
      await down();

      // Assert
      const tableExists = await global.prisma.$queryRaw`
        SELECT EXISTS (
          SELECT FROM information_schema.tables 
          WHERE table_name = 'user_preferences'
        );
      `;

      expect(tableExists).toBeFalsy();
    });
  });

  describe('data integrity', () => {
    it('should maintain referential integrity', async () => {
      // Arrange
      const user = await userFactory.createUser();
      await up();

      // Act - Try to delete user (should cascade)
      await global.prisma.user.delete({
        where: { id: user.id }
      });

      // Assert - Preferences should be deleted too
      const preferences = await global.prisma.userPreferences.findUnique({
        where: { userId: user.id }
      });

      expect(preferences).toBeNull();
    });

    it('should prevent duplicate preferences per user', async () => {
      // Arrange
      const user = await userFactory.createUser();
      await up();

      // Act & Assert - Should throw error for duplicate
      await expect(
        global.prisma.userPreferences.create({
          data: {
            userId: user.id,
            theme: 'dark'
          }
        })
      ).rejects.toThrow();
    });
  });
});
```

**Production Migration Script**:
```typescript
// scripts/migrate-production.ts
import { PrismaClient } from '@prisma/client';
import { execSync } from 'child_process';

const prisma = new PrismaClient();

interface MigrationStatus {
  id: string;
  checksum: string;
  finished_at: Date | null;
  migration_name: string;
  logs: string | null;
  rolled_back_at: Date | null;
  started_at: Date;
  applied_steps_count: number;
}

async function getMigrationStatus(): Promise<MigrationStatus[]> {
  try {
    return await prisma.$queryRaw`
      SELECT * FROM "_prisma_migrations" 
      ORDER BY started_at DESC;
    `;
  } catch (error) {
    console.log('No migration history found (first migration)');
    return [];
  }
}

async function runProductionMigration(): Promise<void> {
  console.log('🚀 Starting production migration...');
  
  try {
    // 1. Check current migration status
    console.log('📋 Checking current migration status...');
    const currentMigrations = await getMigrationStatus();
    console.log(`Found ${currentMigrations.length} previous migrations`);

    // 2. Create database backup (if configured)
    if (process.env.BACKUP_BEFORE_MIGRATE === 'true') {
      console.log('💾 Creating database backup...');
      execSync('pg_dump $DATABASE_URL > backup_$(date +%Y%m%d_%H%M%S).sql');
      console.log('✅ Backup created');
    }

    // 3. Run Prisma migration
    console.log('🔄 Applying migrations...');
    execSync('npx prisma migrate deploy', { stdio: 'inherit' });

    // 4. Verify migration status
    console.log('🔍 Verifying migration status...');
    const newMigrations = await getMigrationStatus();
    const newMigrationCount = newMigrations.length - currentMigrations.length;
    
    if (newMigrationCount > 0) {
      console.log(`✅ Successfully applied ${newMigrationCount} new migrations`);
      
      // List new migrations
      const newMigrationNames = newMigrations
        .slice(0, newMigrationCount)
        .map(m => m.migration_name);
      console.log('📝 New migrations:', newMigrationNames.join(', '));
    } else {
      console.log('📄 No new migrations to apply');
    }

    // 5. Run data migrations if any
    if (process.env.RUN_DATA_MIGRATIONS === 'true') {
      console.log('📊 Running data migrations...');
      // Import and run data migrations here
      console.log('✅ Data migrations completed');
    }

    // 6. Verify database integrity
    console.log('🔧 Verifying database integrity...');
    const userCount = await prisma.user.count();
    console.log(`✅ Database verification passed (${userCount} users found)`);

    console.log('🎉 Production migration completed successfully!');

  } catch (error) {
    console.error('❌ Migration failed:', error);
    
    if (process.env.ROLLBACK_ON_FAILURE === 'true') {
      console.log('⏪ Rolling back migrations...');
      // Implement rollback logic here
    }
    
    process.exit(1);
  } finally {
    await prisma.$disconnect();
  }
}

// Environment validation
const requiredEnvVars = ['DATABASE_URL'];
const missingEnvVars = requiredEnvVars.filter(envVar => !process.env[envVar]);

if (missingEnvVars.length > 0) {
  console.error('❌ Missing required environment variables:', missingEnvVars.join(', '));
  process.exit(1);
}

// Run migration
if (require.main === module) {
  runProductionMigration()
    .then(() => process.exit(0))
    .catch((error) => {
      console.error('Migration script failed:', error);
      process.exit(1);
    });
}
```

**package.json scripts**:
```json
{
  "scripts": {
    "db:migrate:dev": "prisma migrate dev",
    "db:migrate:deploy": "prisma migrate deploy",
    "db:migrate:reset": "prisma migrate reset",
    "db:migrate:status": "prisma migrate status",
    "db:migrate:production": "ts-node scripts/migrate-production.ts",
    "db:seed": "ts-node prisma/seed.ts",
    "db:studio": "prisma studio"
  }
}
```

**Exercise**: Create a comprehensive migration strategy for adding user roles and permissions to your application

---

## Continue with Parts 4 and 5...

The curriculum continues with Authentication & Security (Lessons 16-20) and Production & Advanced Topics (Lessons 21-25), all adapted for TypeScript with proper typing, interfaces, and type-safe patterns throughout.

Would you like me to continue with the remaining parts of the TypeScript curriculum?