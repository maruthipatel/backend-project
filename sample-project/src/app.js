// Task 1: Implement User Authentication with JWT
const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const app = express();
app.use(express.json());

const users = [];

// User registration endpoint
app.post("/register", async (req, res) => {
  try {
    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    const user = { username: req.body.username, password: hashedPassword };
    users.push(user);
    res.status(201).send();
  } catch {
    res.status(500).send();
  }
});

// User login endpoint
app.post("/login", async (req, res) => {
  const user = users.find((user) => user.username === req.body.username);
  if (user == null) {
    return res.status(400).send("User not found");
  }
  try {
    if (await bcrypt.compare(req.body.password, user.password)) {
      const accessToken = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET);
      res.json({ accessToken: accessToken });
    } else {
      res.status(403).send("Invalid password");
    }
  } catch {
    res.status(500).send();
  }
});

// Sample protected route
app.get("/protected", authenticateToken, (req, res) => {
  res.send("Protected route accessed successfully");
});

function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (token == null) {
    return res.sendStatus(401);
  }

  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
    if (err) {
      return res.sendStatus(403);
    }
    req.user = user;
    next();
  });
}

// Task 2: Create API Endpoints for Data Retrieval
const axios = require("axios");
const API_URL = "https://api.publicapis.org/entries";

app.get("/public-api", async (req, res) => {
  try {
    const { data } = await axios.get(API_URL);
    res.json(data);
  } catch (error) {
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// Filtering options for data retrieval based on categories and result limits
app.get("/public-api/filter", async (req, res) => {
  const { category, limit } = req.query;
  let apiUrl = API_URL;
  if (category) {
    apiUrl += `?category=${category}`;
  }
  if (limit) {
    apiUrl += `&limit=${limit}`;
  }

  try {
    const { data } = await axios.get(apiUrl);
    res.json(data);
  } catch (error) {
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// Task 3: Implement Swagger Documentation
const swaggerJsdoc = require("swagger-jsdoc");
const swaggerUi = require("swagger-ui-express");

const swaggerOptions = {
  swaggerDefinition: {
    info: {
      title: "Public APIs Documentation",
      description: "Documentation for public APIs",
      contact: {
        name: "Your Name",
      },
      servers: ["http://localhost:3000"],
    },
  },
  apis: ["app.js"],
};

const swaggerDocs = swaggerJsdoc(swaggerOptions);
app.use("/api-docs", swaggerUi.serve, swaggerUi.setup(swaggerDocs));

/**
 * @swagger
 * /public-api:
 *   get:
 *     summary: Retrieve all public APIs
 *     responses:
 *       200:
 *         description: A list of public APIs
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 type: object
 */

/**
 * @swagger
 * /public-api/filter:
 *   get:
 *     summary: Retrieve public APIs with filtering options
 *     parameters:
 *       - in: query
 *         name: category
 *         schema:
 *           type: string
 *         description: Category to filter APIs
 *       - in: query
 *         name: limit
 *         schema:
 *           type: integer
 *         description: Limit the number of results
 *     responses:
 *       200:
 *         description: A list of public APIs based on filtering options
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 type: object
 */

// Task 4: Secure API Endpoint for Authenticated Users Only
app.get("/restricted", authenticateToken, (req, res) => {
  res.send("You have accessed the restricted endpoint!");
});

// Task 5: Retrieve Ethereum Account Balance with web3.js (Optional)
const Web3 = require("web3");
const web3 = new Web3("https://mainnet.infura.io/v3/YOUR_INFURA_PROJECT_ID");

app.get("/ethereum-balance", async (req, res) => {
  const { address } = req.query;
  if (!address) {
    return res.status(400).json({ error: "Address parameter is required" });
  }

  try {
    const balance = await web3.eth.getBalance(address);
    res.json({ balance: web3.utils.fromWei(balance, "ether") });
  } catch (error) {
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
