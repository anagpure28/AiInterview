const express = require("express");
require("dotenv").config();
const { connection } = require("./Config/db");
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');


const  authRouter  = require("./Routes/auth.route");
const { userRoute } = require("./Routes/user.route");
const cors = require("cors");

const app = express();

app.use(cors());
app.use(express.json());
app.use(bodyParser.json());
app.use("/auth", authRouter)
app.use("/chat", userRoute);

app.listen(process.env.PORT, async () => {
  await connection;
  console.log(`server started on port ${process.env.PORT} `);
});

