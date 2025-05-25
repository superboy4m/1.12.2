
// Модули
const express = require('express');
const fs = require('fs').promises;
const path = require('path');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express(); // Запуск приложения
const port = process.env.PORT || 3000; // Порт

app.use(express.json());
app.use(cors());
app.use(express.static(path.join(__dirname, '..')));

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';
const usersFilePath = path.join(__dirname, 'users.json');
const feedbackFilePath = path.join(__dirname, 'feedback.json');

// Асинхронная функция для чтения файла и парсинга JSON
async function readFile(filePath, defaultReturn = null) {
    try {
        const data = await fs.readFile(filePath, 'utf8'); // Чтение файла в формате utf8
        
        return JSON.parse(data); // Парсинг JSON и возврат данных
    } catch (error) {
        
        if (error.code === 'ENOENT' && defaultReturn !== null) {
            console.warn(`Файл не найден: ${filePath}. Возвращается значение по умолчанию.`); //Если файл не найден и есть значение по умолчанию, возвращаем его
            return defaultReturn;
        }
        
        console.error(`Ошибка при чтении ${path.basename(filePath)}:`, error);
        throw error;
    }
}

// Асинхронная функция для записи данных в файл в виде JSON
async function writeFile(filePath, data) {
    try {
        await fs.writeFile(filePath, JSON.stringify(data, null, 2), 'utf8'); // Запись файла в формате utf8
    } catch (error) {
        console.error(`Ошибка при записи в ${path.basename(filePath)}:`, error);
        throw error;
    }
}

function generateToken(user) {
    const payload = {
        userId: user.email, 
        email: user.email,
        username: user.username
    };
    
    return jwt.sign(payload, JWT_SECRET);
}


function authenticateToken(req, res, next) { // Проверка токена
    
    const authHeader = req.headers.authorization;
    const token = authHeader && authHeader.split(' ')[1];

    
    if (!token) { // Если токен отсутствует, то сброс авторизации (401)
        console.log('Токен не предоставлен');
        return res.sendStatus(401);
    }

    
    jwt.verify(token, JWT_SECRET, (err, user) => { // Проверка токена (снова...)
        if (err) {
            console.error('Ошибка при проверке токена:', err);
            return res.sendStatus(403);
        }
        req.user = user; //Запрос имени пользователя
        next();
    });
}

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, '..', 'index.html')); //Сайт
});

//                           ---Регистрация---
app.post('/register', async (req, res) => {
    const { username, email, password } = req.body;

    console.log('Попытка регистрации:', { username, email });

    
    if (!username || !email || !password) { // Обязательные полея
        console.warn('Отсутствуют поля регистрации');
        return res.status(400).json({ message: 'Заполните все поля' });
    }

    if (password.length < 3) {
        return res.status(400).json({ message: 'Пароль должен содержать не менее 3-х символов' });
    }

    try {
        const users = await readFile(usersFilePath, []);

        const emailExists = users.some(user => user.email.toLowerCase() === email.toLowerCase());  //Совпадение почты
        if (emailExists) {
            console.warn('Почта занята :(');
            return res.status(409).json({ message: 'Почта уже занята' });
        }

        const usernameExists = users.some(user => user.username.toLowerCase() === username.toLowerCase()); //Совпадение имени
        if (usernameExists) {
            console.warn('Имя занято :(');
            return res.status(409).json({ message: 'Имя уже занято' });
        }

        
        const hashedPassword = await bcrypt.hash(password, 10); // Хеш пароля
        
        const newUser = { // Новый пользователь
            username,
            email,
            password: hashedPassword
        };

        users.push(newUser);// Запись нового пользорватьея в users
        await writeFile(usersFilePath, users);

        console.log('Пользователь ${username}успешно зарегистрирован:', email);
        res.status(201).json({ message: 'Регистрация успешна! Авторизуйтесь, чтобы оставлять комментарии' });
    } catch (error) {
        console.error('Ошибка регистрации:', error);
        res.status(500).json({ message: 'Ошибка регистрации' }); // Внутренняя ошибка сервера
    }
});

//                           ---Авторизация---
app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    console.log('Попытка входа:', { email });

  
    try { //Проверка пользователя при авторизации
        const users = await readFile(usersFilePath, []); 
        const user = users.find(user => user.email.toLowerCase() === email.toLowerCase());

        if (!user) {
            console.warn('Попытка авторизации — почта не найдена:', email);
            return res.status(401).json({ message: 'Эта почта не зарегистрирована' }); 
        }

        const passwordMatch = await bcrypt.compare(password, user.password);
        if (!passwordMatch) {
            console.warn('Попытка авторизации — неверный пароль:', email);
            return res.status(401).json({ message: 'Неверный пароль' });
        }

        const token = generateToken(user);
        console.log('Успешный вход:', email);
        res.status(200).json({
            message: 'Login successful.',
            token,
            username: user.username
        });
    } catch (error) {
        console.error('Ошибка при входе:', error); // Непредвиденая ошибка
        res.status(500).json({ message: 'Непредвиденая ошибка' });
    }
});

app.get('/profile', authenticateToken, (req, res) => {
    res.json({
        message: `Welcome, ${req.user.email}!`,
        user: req.user
    });
});
// --- Фидбек/отзыв/комментарий --- 
// Отправка обратной связи
app.post('/feedback', authenticateToken, async (req, res) => {
    const {
        text
    } = req.body;
    const username = req.user.username;

    // Наличие текста отзыва
    if (!text) {
        return res.status(400).json({
        });
    }

    try {
        // Чтение файла обратной связи или создание пустого объекта, если файла нет
        const feedback = await readFile(feedbackFilePath, {});
        // Запись обратной связи, перезаписывая существующую
        feedback[username] = {
            text
        }; // Перезаписываем обратную связь
        await writeFile(feedbackFilePath, feedback);

        console.log(username, 'Оставил/изменил отзыв' );
        res.status(201).json({message: 'Feedback submitted successfully.'});
    } catch (error) {
        console.error('Непредвиденая ошибка', error);
        res.status(500).json({
            message: 'Непредвиденая ошибка'
        });
    }
});

// Получение всех отзывов
app.get('/feedback', async (req, res) => {
    try {
        const feedback = await readFile(feedbackFilePath, {});
        res.status(200).json(feedback);
    } catch (error) {
        console.error('Ошибка чтения', error);
        res.status(500).json({
            message: 'Ошибка записи'
        });
    }
});

// Запуск сервера
app.listen(port, () => {
    console.log(`Сервер работает. Порт: ${port}`);
});
