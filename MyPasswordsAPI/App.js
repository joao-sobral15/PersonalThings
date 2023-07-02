const express = require('express');
const { MongoClient, ServerApiVersion } = require('mongodb');
const bcrypt = require('bcryptjs');
const uri = "mongodb+srv://jsobral:Ac2v0iR3S7Mts4Sn@mypasswords.fxkdtvk.mongodb.net/?retryWrites=true&w=majority";
const bodyParser = require('body-parser');
const { User, PassworsUsers } = require('./models');

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



//Criação de um novo utilizador -- 

app.post('/NewUser', (req, res) => {

  const {name, email,password} = req.body;

  if (!name || !email || !password) {
    return res.status(400).json({ error: 'Todos os campos devem ser preenchidos' });
  }

  const newUser = new  User({
    name,email,password
  });

  newUser.save()
    .then((user) => {
      res.status(201).json(user);
    })
    .catch((error) => {
      res.status(500).json({ error: 'Erro ao criar usuário' });
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
      // Verificar se o usuário foi encontrado
      if (!user) {
        return res.status(404).json({ error: 'Usuário não encontrado' });
      }

      // O usuário foi encontrado com sucesso
      res.status(200).json(user);
    })
    .catch((error) => {
      // Ocorreu um erro ao buscar o usuário
      res.status(500).json({ error: 'Erro ao buscar usuário' });
    });
});


app.post('/users/:id/passwords', (req, res) => {
  const userId = req.params.id;
  const { password,app } = req.body;

  // Verificar se a senha foi fornecida
  if (!password) {
    console.log(password);
    return res.status(400).json({ error: 'A senha deve ser fornecida' });
  }

  // Criar uma nova senha criptografada para o usuário
  bcrypt.hash(password, 10)
    .then((hashedPassword) => {
      // Criar uma nova senha para o usuário
      const newPassword = new PassworsUsers({
        idUser: userId,
        app: app,
        password: hashedPassword,
      });

      newPassword.save()
        .then((newPassword) => {
          // A senha foi criada com sucesso
          res.status(201).json(newPassword);
        })
        .catch((error) => {
          // Ocorreu um erro ao criar a senha
          res.status(500).json({ error: 'Erro ao criar a senha' });
        });
    })
    .catch((error) => {
      // Ocorreu um erro ao criptografar a senha
      res.status(500).json({ error: 'Erro ao criptografar a senha' });
    });
});

app.get('/users/:id/passwords', (req, res) => {
  const userId = req.params.id;

  PassworsUsers.findOne({ idUser: userId })
    .populate('idUser')
    .exec()
    .then((password) => {
      if (!password) {
        return res.status(404).json({ error: 'Usuário não possui senhas cadastradas' });
      }

      const decryptedPassword = bcrypt.compareSync(password.password, password.idUser.password)
        ? password.password
        : 'Senha inválida';

      const decryptedUser = {
        _id: password.idUser._id,
        name: password.idUser.name,
        email: password.idUser.email,
      };

      const decryptedPasswordData = {
        _id: password._id,
        idUser: password.idUser,
        password: decryptedPassword,
        user: decryptedUser,
      };

      res.status(200).json(decryptedPasswordData);
    })
    .catch((error) => {
      res.status(500).json({ error: 'Erro ao buscar senhas do usuário' });
    });
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