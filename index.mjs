import express from 'express';
import { MongoClient, ObjectId } from 'mongodb';
import * as bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import swaggerUi from 'swagger-ui-express';
import swaggerJsdoc from 'swagger-jsdoc';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

import { config } from 'dotenv';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Load environment variables
config();

const app = express();
const port = process.env.PORT;

// Database connection
const client = new MongoClient(process.env.MONGODB_URL);

const connectDB = async () => {
  // Use connect method to connect to the server
  await client.connect();
  console.log('Datbase Connected successfully to server');

  return client.db('app');
};

const db = await connectDB();

// Token Functions
const signJWT = (payload) => {
  return jwt.sign({ user: payload }, process.env.JWT_SECRET, { expiresIn: 60 * 60 });
};

const verifyJWT = (token) => {
  return jwt.verify(token, process.env.JWT_SECRET);
};

// Swagger setup
const swaggerSpec = swaggerJsdoc({
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'Todo API',
      version: '1.0.0',
      description: 'A simple CRUD Todo API with JWT authentication',
    },
    components: {
      securitySchemes: {
        bearerAuth: {
          type: 'http',
          scheme: 'bearer',
          bearerFormat: 'JWT',
        },
      },
      schemas: {
        Todo: {
          type: 'object',
          properties: {
            _id: { type: 'string', example: '665f1a2b3c4d5e6f7a8b9c0d' },
            title: { type: 'string', example: 'Buy groceries' },
            description: { type: 'string', example: 'Milk, eggs, bread' },
            userId: { type: 'string', example: '665f1a2b3c4d5e6f7a8b9c0c' },
          },
        },
        Error: {
          type: 'object',
          properties: {
            message: { type: 'string' },
          },
        },
      },
    },
  },
  apis: [join(__dirname, 'index.mjs')],
});

// Middlewares
app.use(express.json())
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));

const authMiddleware = async (req, res, next) => {
  try {
    if(!req.headers.authorization){
      return res.status(401).json({
        message: "Unauthorized. Please login"
      });
    }


    const token = req.headers.authorization.split(' ')[1]

    const result = verifyJWT(token);

    req.user = result.user;

     return next();
  } catch (error) {
     return res.json({
      message: 'Auth Error',
      error: error.message,
    });
  }
}

// API Routes

/**
 * @openapi
 * /:
 *   get:
 *     summary: Health check
 *     responses:
 *       200:
 *         description: API is running
 */
app.get('/', (req, res) => {
  res.json({
    message: 'Helloo World',
  });
});

/**
 * @openapi
 * /register:
 *   post:
 *     summary: Register a new user
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [name, email, password]
 *             properties:
 *               name:
 *                 type: string
 *                 example: Alice
 *               email:
 *                 type: string
 *                 example: alice@example.com
 *               password:
 *                 type: string
 *                 example: secret123
 *     responses:
 *       201:
 *         description: User registered successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 status:
 *                   type: string
 *                   example: success
 *                 data:
 *                   type: object
 *                   properties:
 *                     userId:
 *                       type: string
 *       422:
 *         description: Validation error
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 */
app.post('/register', async (req, res) => {
  try {
    // Extract request body
    const { name, email, password } = req.body;

    // Encrypt password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Add it to database
    const result = await db
      .collection('users')
      .insertOne({ name, email, password: hashedPassword });

    return res.status(201).json({
      status: 'success',
      message: 'User Registered Successfully',
      data: { userId: result.insertedId },
    });
  } catch (error) {
    return res.json({
      message: 'Error',
      error: error.message,
    });
  }
});

/**
 * @openapi
 * /login:
 *   post:
 *     summary: Login and receive a JWT token
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [email, password]
 *             properties:
 *               email:
 *                 type: string
 *                 example: alice@example.com
 *               password:
 *                 type: string
 *                 example: secret123
 *     responses:
 *       200:
 *         description: Login successful
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 status:
 *                   type: string
 *                   example: success
 *                 data:
 *                   type: object
 *                   properties:
 *                     token:
 *                       type: string
 *       422:
 *         description: Invalid credentials
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 */
app.post('/login', async (req, res) => {
  try {
    // Extract request body
    const { email, password } = req.body;

    // Verify user
    let user = await db.collection('users').findOne({ email });

    if (!user) {
      return res.status(422).json({
        message: 'Invalid credentials',
      });
    }

    const isValidPassword = await bcrypt.compare(password, user.password);

    if (!isValidPassword) {
      return res.status(422).json({
        message: 'Invalid credentials',
      });
    }

    // Slim user object creation
    user = {id: user._id, name: user.name, email: user.email};

    // Sign JWT token
    const token = signJWT(user);

    return res.status(200).json({
      status: 'success',
      message: 'User Login Successfully',
      data: { token },
    });
  } catch (error) {
    return res.json({
      message: 'Error',
      error: error.message,
    });
  }
});

/**
 * @openapi
 * /todos:
 *   get:
 *     summary: Get all todos for the authenticated user
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: page
 *         schema:
 *           type: integer
 *           default: 1
 *       - in: query
 *         name: limit
 *         schema:
 *           type: integer
 *           default: 10
 *     responses:
 *       200:
 *         description: List of todos
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 status:
 *                   type: string
 *                 data:
 *                   type: array
 *                   items:
 *                     $ref: '#/components/schemas/Todo'
 *                 page:
 *                   type: integer
 *                 limit:
 *                   type: integer
 *                 total:
 *                   type: integer
 *       401:
 *         description: Unauthorized
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 */
app.get('/todos', authMiddleware, async(req, res) => {
  try {
    let {page, limit} = req.query;

    page = parseInt(page, 10) || 1;
    limit = parseInt(limit, 10) || 10;

    // Fetch todos for that user
    const totalTodos = await db.collection('todos').countDocuments({ userId: new ObjectId(req.user.id) });

    const result = await db
      .collection('todos')
      .find({ userId: new ObjectId(req.user.id) })
      .limit(limit)
      .skip((page - 1) * limit)
      .toArray();

    return res.status(200).json({
      status: 'success',
      message: 'Todos Fetched Successfully',
      data: result,
      page: page,
      limit: limit,
      total: totalTodos
    });
  } catch (error) {
    return res.json({
      message: 'Error',
      error: error.message,
    });
  }
});

/**
 * @openapi
 * /todos:
 *   post:
 *     summary: Create a new todo
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [title, description]
 *             properties:
 *               title:
 *                 type: string
 *                 example: Buy groceries
 *               description:
 *                 type: string
 *                 example: Milk, eggs, bread
 *     responses:
 *       201:
 *         description: Todo created
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 status:
 *                   type: string
 *                 data:
 *                   type: object
 *                   properties:
 *                     todoId:
 *                       type: string
 *       401:
 *         description: Unauthorized
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 */
app.post('/todos', authMiddleware, async(req, res) => {
  try {
    const {title, description} = req.body;

    console.log("User ID" + req.user.id);

     // Add it to database
    const result = await db
      .collection('todos')
      .insertOne({ title, description, userId: new ObjectId(req.user.id) });

    return res.status(201).json({
      status: 'success',
      message: 'Todo Created Successfully',
      data: { todoId: result.insertedId },
    });
  } catch (error) {
    return res.json({
      message: 'Error',
      error: error.message,
    });
  }
});

/**
 * @openapi
 * /todos/{id}:
 *   put:
 *     summary: Update a todo
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         example: 665f1a2b3c4d5e6f7a8b9c0d
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               title:
 *                 type: string
 *                 example: Buy groceries (updated)
 *               description:
 *                 type: string
 *                 example: Milk, eggs, bread, butter
 *     responses:
 *       200:
 *         description: Todo updated
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 status:
 *                   type: string
 *                 data:
 *                   $ref: '#/components/schemas/Todo'
 *       401:
 *         description: Unauthorized
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       403:
 *         description: Forbidden — you don't own this todo
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       404:
 *         description: Todo not found
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 */
app.put('/todos/:id', authMiddleware, async(req, res) => {
  try {
    const {id} = req.params;
    const {title, description} = req.body;

    // Check if the auth user is the owner
    let todo = await db.collection('todos').findOne({ _id: new ObjectId(id) })

    if (!todo) {
      return res.status(404).json({ message: 'Todo not found' });
    }

    if(todo.userId.toString() !== req.user.id){
      return res.status(403).json({
        message: "You don't own this todo"
      });
    }

     // Add it to database
    const result = await db
      .collection('todos')
      .updateOne({_id: new ObjectId(id)}, { $set: { title, description } });

    todo = await db.collection('todos').findOne({_id: new ObjectId(id)})

    return res.status(200).json({
      status: 'success',
      message: 'Todo Updated Successfully',
      data: todo,
    });

  } catch (error) {
    return res.json({
      message: 'Error',
      error: error.message,
    });
  }
});

/**
 * @openapi
 * /todos/{id}:
 *   delete:
 *     summary: Delete a todo
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         example: 665f1a2b3c4d5e6f7a8b9c0d
 *     responses:
 *       200:
 *         description: Todo deleted
 *       401:
 *         description: Unauthorized
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       403:
 *         description: Forbidden — you don't own this todo
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       404:
 *         description: Todo not found
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 */
app.delete('/todos/:id', authMiddleware, async(req, res) => {
  try {
    const {id} = req.params;

    // Check if the auth user is the owner
    const todo = await db.collection('todos').findOne({ _id: new ObjectId(id) })

    if (!todo) {
      return res.status(404).json({ message: 'Todo not found' });
    }

    if(todo.userId.toString() !== req.user.id){
      return res.status(403).json({
        message: "You don't own this todo"
      });
    }

    // Delete it from database
    const result = await db
      .collection('todos')
      .deleteOne({_id: new ObjectId(id)});

    return res.status(200).json({
      status: 'success',
      message: 'Todo Deleted Successfully'
    });

  } catch (error) {
    return res.json({
      message: 'Error',
      error: error.message,
    });
  }
});


app.listen(port, () => {
  console.log(`Todo list app listening on port ${port}`);
});
