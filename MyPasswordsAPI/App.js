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

// Função para descriptografar a senha
function decryptPassword(encryptedPassword, secretKey, iv) {
  const decipher = crypto.createDecipheriv('aes-256-cbc', secretKey, iv);
  let decrypted = decipher.update(encryptedPassword, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}
//Criação de um novo utilizador -- 

app.post('/NewUser', (req, res) => {
  const { name, email, password } = req.body;

  if (!name || !email || !password) {
    return res.status(400).json({ error: 'Todos os campos devem ser preenchidos' });
  }

  // Encripta a senha
  bcrypt.genSalt(10, (err, salt) => {
    bcrypt.hash(password, salt, (err, hash) => {
      if (err) {
        return res.status(500).json({ error: 'Erro ao encriptar a senha' });
      }

      const newUser = new User({
        name,
        email,
        password: hash, // Armazena a senha encriptada
      });

      newUser.save()
        .then((user) => {
          res.status(201).json(user);
        })
        .catch((error) => {
          res.status(500).json({ error: 'Erro ao criar usuário', error });
        });
    });
  });
});

app.get('/users', (req, res) => {
  User.find()
    .then((users) => {
      // Os usuários foram encontrados com sucesso
      res.status(200).json(users);
    })
    .catch((error) => {
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

