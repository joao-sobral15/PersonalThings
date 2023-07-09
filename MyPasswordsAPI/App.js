const express = require('express');
const { MongoClient, ServerApiVersion } = require('mongodb');
const bcrypt = require('bcryptjs');
const bodyParser = require('body-parser');
const { User, PassworsUsers } = require('./models');
const crypto = require('crypto');
const mongoclient = require('mongoclient');
const { mongo, Mongoose } = require('mongoose');
require('dotenv').config();
const uri = process.env.CONN_STRING;
const secretKey = Buffer.from(process.env.SECRET_KEY, 'hex');
const jwt = require('jsonwebtoken');


const iv = Buffer.from(process.env.IV, 'hex');
const client = new MongoClient(uri, {
    serverApi: {
      version: ServerApiVersion.v1,
      strict: true,
      deprecationErrors: true,
    }
  });
const app = express();

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

app.get('/', (req, res) => {
  res.send('Olá, mundo! Este é o meu servidor Express.js.');
});

function encryptPassword(password) {
  console.log(secretKey);
  console.log(iv);
  const cipher = crypto.createCipheriv('aes-256-cbc', secretKey,iv);
  let encrypted = cipher.update(password, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return encrypted;
}
function generateToken(userId) {
  const token = jwt.sign({ userId }, secretKey, { expiresIn: '1h' });
  return token;
}

function authenticateToken(req, res, next) {
  const token = req.headers['authorization'];

  if (!token) {
    return res.status(401).json({ error: 'Token de autenticação não fornecido' });
  }

  jwt.verify(token, secretKey, (err, decoded) => {
    if (err) {
      return res.status(401).json({ error: 'Token de autenticação inválido' });
    }

    req.userId = decoded.userId;
    next();
  });
}

app.post('/register', async (req, res) => {
  const { name, email, password } = req.body;

  if (!name || !email || !password) {
    return res.status(400).json({ error: 'Todos os campos devem ser preenchidos' });
  }

  try {
    // Verificar se o usuário já está registrado
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: 'Email já está sendo usado' });
    }

    // Encriptar a senha
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Criar um novo usuário
    const newUser = new User({
      name,
      email,
      password: hashedPassword
    });

    await newUser.save();

    // Gerar um token JWT
    const token = generateToken(newUser._id);

    res.status(201).json({user: newUser._id, token: token });
  } catch (error) {
    console.error('Erro ao registrar usuário', error);
    res.status(500).json({ error: 'Erro ao registrar usuário' });
  }
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Todos os campos devem ser preenchidos' });
  }

  try {
    // Verificar se o usuário existe
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ error: 'Credenciais inválidas' });
    }

    // Verificar a senha
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ error: 'Credenciais inválidas',  });
    }

    // Gerar um JWT (JSON Web Token)
    const token = jwt.sign({ userId: user._id }, secretKey, { expiresIn: '1h' });

    res.json({user: user._id, token: token });
  } catch (error) {
    console.error('Erro ao fazer login', error);
    res.status(500).json({ error: 'Erro ao fazer login' });
  }
});

// Função para descriptografar a senha
function decryptPassword(encryptedPassword, secretKey, iv) {
  const decipher = crypto.createDecipheriv('aes-256-cbc', secretKey, iv);
  let decrypted = decipher.update(encryptedPassword, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}
//Criação de um novo utilizador -- 


app.get('/users', (req, res) => {
  User.find()
    .then((users) => {
      // Os usuários foram encontrados com sucesso
      res.status(200).json(users);
    })
    .catch((error) => {
      console.log(error);
      // Ocorreu um erro ao buscar os usuários
      res.status(500).json({ error: 'Erro ao buscar usuários' });
    });
});

app.get('/users/:id', (req, res) => {
  const userId = req.params.id;

  User.findById(userId)
    .then((user) => {
      if (!user) {
        return res.status(404).json({ error: 'Usuário não encontrado' });
      }

      res.status(200).json(user);
    })
    .catch((error) => {
      console.log(error);
      res.status(500).json({ error: 'Erro ao buscar usuário' });
    });
});

app.post('/passwords', async (req, res) => {
  try {
    const { user, app, password } = req.body;

    const encryptedPassword = encryptPassword(password);

    const newPassword = new PassworsUsers({
      _idUser: user,
      app: app,
      password: encryptedPassword
    });

    await newPassword.save();
    res.status(200).json({newPassword });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Erro ao criar a senha' });
  }
});

app.get('/passwords/all', async (req, res) => {
  try {
    const user = req.body.userId;
    const passwords = await PassworsUsers.find({ _idUser: user });

    if (passwords.length === 0) {
      return res.status(404).json({ error: 'Senha não encontrada' });
    }

    const decryptedPasswords = passwords.map(password => ({
      app: password.app
    }));

    res.json(decryptedPasswords);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Erro ao obter a senha' });
  }
});

app.get('/passwords/:userId', async (req, res) => {
  try {
    const user = req.params.userId;
    const app = req.body.app;
    const password = await PassworsUsers.findOne({ _idUser: user, app: app });

    if (!password) {
      return res.status(404).json({ error: 'Senha não encontrada' });
    }

    const decryptedPassword = {
      app: password.app,
      password: decryptPassword(password.password, secretKey, iv)
    };

    res.json(decryptedPassword);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Erro ao obter a senha' });
  }
});

const port = 3000;
// Iniciar o servidor
app.listen(port, async () => {
  try {
    // Criar uma nova instância do cliente do MongoDB
    const client = new MongoClient(uri, { useNewUrlParser: true });
    // Conectar ao servidor do MongoDB
    await client.connect();

    console.log('Conectado ao banco de dados');

    // Retornar a instância do cliente do MongoDB
    return client;
  } catch (error) {
    console.error('Erro ao conectar ao banco de dados', error);
  }
});

