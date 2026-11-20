
import express from 'express';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';

const app = express();
const PORT = 3000;
const JWT_SECRET = 'my_secret_key';

app.use(express.json());

const users = [
    {
        id: 1,
        username: 'admin',
        email: 'admin@gmail.com',
        password: await bcrypt.hash('admin123', 10),
        role: 'admin'
    },
    {
        id: 2,
        username: 'user',
        email: 'user@gmail.com',
        password: await bcrypt.hash('user123', 10),
        role: 'user'
    }
];


function authenticateJWT(req, res, next) {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({
            message: 'Токен отсутствует'
        });
    }

    const token = authHeader.split(' ')[1];

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(403).json({
                message: 'Недействительный или просроченный токен'
            });
        }

        req.user = decoded;
        next();
    });
}


function authorizeRole(role) {
    return (req, res, next) => {
        if (req.user.role !== role) {
            return res.status(403).json({
                message: 'Недостаточно прав доступа'
            });
        }

        next();
    };
}


app.get('/', (req, res) => {
    res.json({
        message: 'Server is running!'
    });
});


app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        const user = users.find(user => user.email === email);

        if (!user) {
            return res.status(404).json({
                message: 'Пользователь не найден'
            });
        }

        const isPasswordValid = await bcrypt.compare(
            password,
            user.password
        );

        if (!isPasswordValid) {
            return res.status(401).json({
                message: 'Неверный пароль'
            });
        }

        const token = jwt.sign(
            {
                id: user.id,
                username: user.username,
                role: user.role
            },
            JWT_SECRET,
            { expiresIn: '15m' }
        );

        res.json({
            message: 'Авторизация успешна',
            token
        });

    } catch (error) {
        res.status(500).json({
            message: 'Ошибка сервера'
        });
    }
});


app.put('/update-email', authenticateJWT, (req, res) => {
    try {
        const { email } = req.body;

        if (!email) {
            return res.status(400).json({
                message: 'Укажите новый email'
            });
        }

        const user = users.find(user => user.id === req.user.id);

        if (!user) {
            return res.status(404).json({
                message: 'Пользователь не найден'
            });
        }

        user.email = email;

        res.json({
            message: 'Email успешно обновлён',
            user: {
                id: user.id,
                username: user.username,
                email: user.email
            }
        });

    } catch (error) {
        res.status(500).json({
            message: 'Ошибка при обновлении email'
        });
    }
});


app.delete('/delete-account', authenticateJWT, (req, res) => {
    try {
        const user = users.find(user => user.id === req.user.id);

        if (!user) {
            return res.status(404).json({
                message: 'Пользователь не найден'
            });
        }

        const updatedUsers = users.filter(
            user => user.id !== req.user.id
        );

        users.splice(0, users.length, ...updatedUsers);

        res.json({
            message: 'Аккаунт успешно удалён'
        });

    } catch (error) {
        res.status(500).json({
            message: 'Ошибка при удалении аккаунта'
        });
    }
});


app.put(
    '/update-role',
    authenticateJWT,
    authorizeRole('admin'),
    (req, res) => {
        try {
            const { id, role } = req.body;

            if (!id || !['admin', 'user'].includes(role)) {
                return res.status(400).json({
                    message: 'Укажите корректные ID и роль'
                });
            }

            const user = users.find(
                user => user.id === Number(id)
            );

            if (!user) {
                return res.status(404).json({
                    message: 'Пользователь не найден'
                });
            }

            user.role = role;

            res.json({
                message: 'Роль пользователя успешно обновлена',
                user: {
                    id: user.id,
                    username: user.username,
                    role: user.role
                }
            });

        } catch (error) {
            res.status(500).json({
                message: 'Ошибка при обновлении роли'
            });
        }
    }
);


app.post('/refresh-token', authenticateJWT, (req, res) => {
    try {
        const user = users.find(
            user => user.id === req.user.id
        );

        if (!user) {
            return res.status(404).json({
                message: 'Пользователь не найден'
            });
        }

        const newToken = jwt.sign(
            {
                id: user.id,
                username: user.username,
                role: user.role
            },
            JWT_SECRET,
            { expiresIn: '15m' }
        );

        res.json({
            message: 'Токен успешно обновлён',
            token: newToken
        });

    } catch (error) {
        res.status(500).json({
            message: 'Ошибка при обновлении токена'
        });
    }
});


app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
