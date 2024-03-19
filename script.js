import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import session from "express-session"; // Import express-session
import path from "path";
import { fileURLToPath } from "url";
import bcrypt from "bcrypt"; // Import bcrypt for password hashing

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const port = 3000;

const db = new pg.Client({
  user: "postgres",
  host: "localhost",
  database: "rpa",
  password: "200200",
  port: 5432,
});
db.connect();

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.json()); // for parsing application/json
app.use(express.static("public"));
// app.use(express.static(path.join(__dirname, "styles")));
// app.use(express.static(path.join(__dirname, "images")));

// Configure express-session middleware
app.use(
  session({
    secret: "Secrets_have_a_cost", // Set a secret key for session encryption
    resave: false,
    saveUninitialized: true,
  })
);

// Route to serve the login.html file
app.get("/", (req, res) => {
  res.sendFile("login.html", { root: __dirname }); // Use the calculated __dirname here
});

// Route to handle user sign-in
app.post("/signin", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).send("Email and password are required");
  }

  try {
    const userQuery = await db.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);

    if (userQuery.rows.length === 0) {
      return res.status(401).send("Invalid email or password");
    }

    const user = userQuery.rows[0];

    const passwordMatch = await bcrypt.compare(password, user.password);

    if (passwordMatch) {
      // Assuming you handle sessions or tokens here
      res.send("User logged in successfully");
    } else {
      res.status(401).send("Incorrect password");
    }
  } catch (error) {
    console.error("Error signing in:", error);
    res.status(500).send("An error occurred while signing in");
  }
});

// Route to handle user registration
app.post("/register", async (req, res) => {
  const { name, email, password } = req.body;

  try {
    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert the new user into the database with hashed password
    const newUserQuery = await db.query(
      "INSERT INTO users (name, email, password) VALUES ($1, $2, $3) RETURNING *",
      [name, email, hashedPassword]
    );

    const newUser = newUserQuery.rows[0];

    // Store user data in session
    req.session.user = {
      id: newUser.id,
      name: newUser.name,
      email: newUser.email,
    };

    res.send("User registered successfully");
  } catch (error) {
    console.error("Error registering user:", error);
    res.status(500).send("An error occurred while registering user");
  }
});

// Start the server
app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
