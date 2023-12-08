/* Imports */
require("dotenv").config()
const express = require("express")
const mongoose = require("mongoose")
const bcrypt = require("bcrypt")
const jwt = require("jsonwebtoken")

const app = express()

// Config JSON response
app.use(express.json())

// Models
const User = require("./models/User")

// Public Route
app.get("/", (req, res) => {
    res.status(200).json({ mensagem: "Bem-vindo à API" })
})

// Sign Up (Criação de Cadastro)
app.post("/signup", async (req, res) => {
    const { nome, email, senha, telefones } = req.body

    try {
        // Check if user exists
        const userExist = await User.findOne({ email: email })

        if (userExist) {
            return res.status(422).json({ mensagem: "E-mail já existente" })
        }

        // Create password hash
        const salt = await bcrypt.genSalt(12)
        const passwordHash = await bcrypt.hash(senha, salt)

        // Create user
        const user = new User({
            nome,
            email,
            senha: passwordHash,
            telefones,
        })

        await user.save()

        const token = generateToken(user._id)

        res.status(201).json({
            id: user._id,
            data_criacao: user.createdAt,
            data_atualizacao: user.updatedAt,
            ultimo_login: user.ultimo_login,
            token: token,
        })
    } catch (error) {
        console.error(error)
        res.status(500).json({ mensagem: "Erro no servidor, tente novamente mais tarde" })
    }
})

// Sign In (Autenticação)
app.post("/signin", async (req, res) => {
    const { email, senha } = req.body

    try {
        // Check if user exists
        const user = await User.findOne({ email: email })

        if (!user || !(await bcrypt.compare(senha, user.senha))) {
            return res.status(401).json({ mensagem: "Usuário e/ou senha inválidos" })
        }

        user.ultimo_login = new Date()
        await user.save()

        const token = generateToken(user._id)

        res.status(200).json({
            id: user._id,
            data_criacao: user.createdAt,
            data_atualizacao: user.updatedAt,
            ultimo_login: user.ultimo_login,
            token: token,
        })
    } catch (error) {
        console.error(error)
        res.status(500).json({ mensagem: "Erro no servidor, tente novamente mais tarde" })
    }
})


// Buscar Usuário
app.get("/user", checkToken, async (req, res) => {
    const userId = req.userId;

    try {
        const user = await User.findById(userId, "-senha");

        if (!user) {
            return res.status(404).json({ mensagem: "Usuário não encontrado" });
        }

        res.status(200).json({ user });
    } catch (error) {
        console.error(error);
        res.status(500).json({ mensagem: "Erro no servidor, tente novamente mais tarde" });
    }
});

// Token Checking Middleware
function checkToken(req, res, next) {
    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1];

    if (!token) {
        return res.status(401).json({ mensagem: "Não autorizado" });
    }

    try {
        const decoded = jwt.verify(token, process.env.SECRET);
        req.userId = decoded.id;
        next();
    } catch (error) {
        if (error.name === 'TokenExpiredError') {
            return res.status(401).json({ mensagem: "Sessão inválida" });
        } else {
            return res.status(401).json({ mensagem: "Não autorizado" });
        }
    }
}

// Credentials
const dbUser = process.env.DB_USER;
const dbPassword = process.env.DB_PASS;

mongoose
    .connect(
        `mongodb+srv://${dbUser}:${dbPassword}@cluster0.tddyvig.mongodb.net/?retryWrites=true&w=majority`,
    )
    .then(() => {
        app.listen(3000);
        console.log("Conectou ao banco!");
    })
    .catch((err) => console.log(err));
