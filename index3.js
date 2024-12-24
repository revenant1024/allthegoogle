import OpenAI from 'openai';
import dotenv from 'dotenv';
import express from 'express';
import bodyParser from 'body-parser';
import cors from 'cors';
import path from 'path';
import { fileURLToPath } from 'url';
import session from 'express-session';
import passport from 'passport';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import { Strategy as KakaoStrategy } from 'passport-kakao';
import { Strategy as NaverStrategy } from 'passport-naver';
import mysql from 'mysql2/promise';
import bcrypt from 'bcrypt';

// __dirname 설정 (ES 모듈 환경용)
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// 환경 변수 로드
dotenv.config();

// Express 앱 생성
const app = express();

// 세션 설정
app.use(
    session({
        secret: process.env.SESSION_SECRET || 'your_secret_key',
        resave: false,
        saveUninitialized: true,
    })
);

// 미들웨어 설정
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(passport.initialize());
app.use(passport.session());

// MySQL 데이터베이스 연결 설정
let db;
(async () => {
    try {
        db = await mysql.createConnection({
            host: process.env.DB_HOST || 'localhost',
            user: process.env.DB_USER || 'root',
            password: process.env.DB_PASSWORD || '',
            database: process.env.DB_NAME || 'allthe',
            port: process.env.DB_PORT || 3307,
        });
        console.log('MySQL Connected');
    } catch (err) {
        console.error('MySQL Connection Error:', err);
    }
})();

// 회원가입 API
app.post('/register', async (req, res) => {
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
        return res.status(400).json({ error: 'Missing required fields' });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        await db.execute(
            'INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
            [username, email, hashedPassword]
        );
        res.status(201).json({ message: 'User registered successfully' });
    } catch (error) {
        if (error.code === 'ER_DUP_ENTRY') {
            res.status(400).json({ error: 'Email already registered' });
        } else {
            console.error('Register Error:', error);
            res.status(500).json({ error: 'Failed to register user' });
        }
    }
});

// 로그인 API
app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: 'Missing email or password' });
    }

    try {
        const [rows] = await db.execute('SELECT * FROM users WHERE email = ?', [email]);

        if (rows.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        const user = rows[0];
        const isPasswordValid = await bcrypt.compare(password, user.password);

        if (!isPasswordValid) {
            return res.status(401).json({ error: 'Invalid password' });
        }

        req.session.user = {
            id: user.id,
            username: user.username,
            email: user.email,
        };

        res.json({ message: 'Login successful', user: req.session.user });
    } catch (error) {
        console.error('Login Error:', error);
        res.status(500).json({ error: 'Failed to login' });
    }
});

// 로그아웃 API
app.post('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            return res.status(500).json({ error: 'Failed to logout' });
        }
        res.json({ message: 'Logout successful' });
    });
});

// 마이페이지 API
app.get('/mypage', (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    res.json(req.session.user);
});

// 사용자 정보 조회 API
app.get('/api/users', async (req, res) => {
    try {
        const [users] = await db.execute(
            'SELECT id, username, email, provider, provider_id, profile_picture FROM users'
        );
        res.json(users);
    } catch (error) {
        console.error('Error fetching users:', error);
        res.status(500).json({ error: 'Failed to fetch users' });
    }
});

// 사용자 삭제 API
app.delete('/api/users/:id', async (req, res) => {
    const userId = req.params.id;
    try {
        await db.execute('DELETE FROM users WHERE id = ?', [userId]);
        res.json({ message: 'User deleted successfully' });
    } catch (error) {
        console.error('Error deleting user:', error);
        res.status(500).json({ error: 'Failed to delete user' });
    }
});

// 소셜 로그인 설정
passport.use(
    new GoogleStrategy(
        {
            clientID: process.env.GOOGLE_CLIENT_ID,
            clientSecret: process.env.GOOGLE_CLIENT_SECRET,
            callbackURL: '/auth/google/callback',
        },
        async (accessToken, refreshToken, profile, done) => {
            try {
                const [rows] = await db.execute(
                    'SELECT * FROM users WHERE provider = ? AND provider_id = ?',
                    ['google', profile.id]
                );

                if (rows.length === 0) {
                    const [result] = await db.execute(
                        'INSERT INTO users (username, email, provider, provider_id, profile_picture) VALUES (?, ?, ?, ?, ?)',
                        [
                            profile.displayName,
                            profile.emails[0]?.value,
                            'google',
                            profile.id,
                            profile.photos[0]?.value,
                        ]
                    );
                    return done(null, { id: result.insertId, ...profile });
                }
                return done(null, rows[0]);
            } catch (error) {
                console.error('Google Auth Error:', error);
                return done(error, null);
            }
        }
    )
);

passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
    try {
        const [rows] = await db.execute('SELECT * FROM users WHERE id = ?', [id]);
        if (rows.length > 0) {
            done(null, rows[0]);
        } else {
            done(new Error('User not found'), null);
        }
    } catch (error) {
        done(error, null);
    }
});

// 소셜 로그인 경로
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
app.get(
    '/auth/google/callback',
    passport.authenticate('google', { failureRedirect: '/' }),
    (req, res) => {
        res.redirect('/mypage');
    }
);

// OpenAI API 요청 함수
async function getChatCompletion(userMessage) {
    try {
        const completion = await openai.chat.completions.create({
            model: "gpt-3.5-turbo",
            messages: [
                { role: "system", content: "당신은 ALLTHE라는 정보 검색 서비스의 조력자입니다. ALLTHE는 각종 플랫폼, 노마드, 사이트 정보를 담고 있습니다." },
                { role: "user", content: userMessage } // 사용자의 메시지를 추가
            ]
        });

        const hallo = completion.choices[0].message.content; // 응답을 hallo 변수에 저장
        console.log(hallo); // 응답을 콘솔에 출력
        return hallo; // hallo 값을 반환
    } catch (error) {
        console.error("Error with OpenAI API:", error.response ? error.response.data : error.message);
        throw new Error('Failed to get response from OpenAI API');
    }
}

// Passport 직렬화/역직렬화 설정
passport.serializeUser((user, done) => {
    done(null, user);
});

passport.deserializeUser((user, done) => {
    done(null, user);
});
passport.use(
    new GoogleStrategy(
        {
            clientID: process.env.GOOGLE_CLIENT_ID,
            clientSecret: process.env.GOOGLE_CLIENT_SECRET,
            callbackURL: '/auth/google/callback',
        },
        async (accessToken, refreshToken, profile, done) => {
            try {
                // 데이터베이스에서 사용자 확인
                const [rows] = await db.execute(
                    'SELECT * FROM users WHERE provider = ? AND provider_id = ?',
                    ['google', profile.id]
                );

                let user;
                if (rows.length === 0) {
                    // 사용자가 없으면 데이터베이스에 삽입
                    const [result] = await db.execute(
                        'INSERT INTO users (username, email, provider, provider_id, profile_picture) VALUES (?, ?, ?, ?, ?)',
                        [
                            profile.displayName,
                            profile.emails[0]?.value,
                            'google',
                            profile.id,
                            profile.photos[0]?.value,
                        ]
                    );
                    // 삽입된 사용자 정보
                    user = {
                        id: result.insertId,
                        username: profile.displayName,
                        email: profile.emails[0]?.value,
                    };
                } else {
                    // 기존 사용자 정보 로드
                    user = rows[0];
                }

                // 세션에 사용자 정보 저장
                return done(null, user);
            } catch (err) {
                console.error('Google Auth Error:', err);
                return done(err, null);
            }
        }
    )
);

// Kakao OAuth 설정
passport.use(
    new KakaoStrategy(
        {
            clientID: process.env.KAKAO_CLIENT_ID,
            callbackURL: '/auth/kakao/callback',
        },
        async (accessToken, refreshToken, profile, done) => {
            try {
                const [rows] = await db.execute(
                    'SELECT * FROM users WHERE provider = ? AND provider_id = ?',
                    ['kakao', profile.id]
                );

                let user;
                if (rows.length === 0) {
                    // 사용자 정보를 DB에 저장
                    const [result] = await db.execute(
                        'INSERT INTO users (username, provider, provider_id, profile_picture) VALUES (?, ?, ?, ?)',
                        [
                            profile.displayName || profile.username,
                            'kakao',
                            profile.id,
                            profile._json.properties?.profile_image,
                        ]
                    );
                    user = {
                        id: result.insertId,
                        username: profile.displayName || profile.username,
                    };
                } else {
                    // 기존 사용자 정보 로드
                    user = rows[0];
                }

                return done(null, user); // 세션에 저장할 사용자 정보 반환
            } catch (err) {
                console.error('Kakao Auth Error:', err);
                return done(err, null);
            }
        }
    )
);

// Naver OAuth 설정
passport.use(
    new NaverStrategy(
        {
            clientID: process.env.NAVER_CLIENT_ID,
            clientSecret: process.env.NAVER_CLIENT_SECRET,
            callbackURL: '/auth/naver/callback',
        },
        async (accessToken, refreshToken, profile, done) => {
            try {
                const [rows] = await db.execute(
                    'SELECT * FROM users WHERE provider = ? AND provider_id = ?',
                    ['naver', profile.id]
                );

                let user;
                if (rows.length === 0) {
                    // 사용자 정보를 DB에 저장
                    const [result] = await db.execute(
                        'INSERT INTO users (username, email, provider, provider_id, profile_picture) VALUES (?, ?, ?, ?, ?)',
                        [
                            profile.displayName,
                            profile.emails[0]?.value,
                            'naver',
                            profile.id,
                            profile._json.profile_image,
                        ]
                    );
                    user = {
                        id: result.insertId,
                        username: profile.displayName,
                        email: profile.emails[0]?.value,
                    };
                } else {
                    // 기존 사용자 정보 로드
                    user = rows[0];
                }

                return done(null, user); // 세션에 저장할 사용자 정보 반환
            } catch (err) {
                console.error('Naver Auth Error:', err);
                return done(err, null);
            }
        }
    )
);

// 직렬화 및 역직렬화
passport.serializeUser((user, done) => {
    done(null, user.id); // 세션에 사용자 ID만 저장
});

passport.deserializeUser(async (id, done) => {
    try {
        const [rows] = await db.execute('SELECT * FROM users WHERE id = ?', [id]);
        if (rows.length > 0) {
            done(null, rows[0]); // 세션에서 사용자 정보 복원
        } else {
            done(new Error('User not found'), null);
        }
    } catch (err) {
        done(err, null);
    }
});

// 소셜 로그인 요청 경로
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
app.get('/auth/kakao', passport.authenticate('kakao'));
app.get('/auth/naver', passport.authenticate('naver'));

// 소셜 로그인 콜백 경로
app.get(
    '/auth/google/callback',
    passport.authenticate('google', { failureRedirect: '/' }),
    (req, res) => {
        // 로그인 성공 후 프론트엔드로 리다이렉트
        res.redirect('/mypage'); // 프론트엔드의 마이페이지 경로
    }
);

app.get(
    '/auth/kakao/callback',
    passport.authenticate('kakao', { failureRedirect: '/' }),
    (req, res) => {
        res.redirect('/mypage');
    }
);

app.get(
    '/auth/naver/callback',
    passport.authenticate('naver', { failureRedirect: '/' }),
    (req, res) => {
        res.redirect('/mypage');
    }
);


// Express 서버 설정 및 실행 함수
function startServer() {
    app.use(cors()); // CORS 설정 추가
    app.use(bodyParser.json());
    app.use(bodyParser.urlencoded({ extended: true }));

    // 정적 파일 경로 설정
    const frontendPath = path.join(__dirname, '../frontend');
    app.use(express.static(frontendPath));

    // 기본 경로에서 index.html 제공
    app.get('/', (req, res) => {
        res.sendFile(path.join(frontendPath, 'index.html'));
    });

    // OpenAI POST 요청 처리
    app.post('/hallo', async (req, res) => {
        const userMessage = req.body.message;
        try {
            const hallo = await getChatCompletion(userMessage);
            res.json({ response: hallo });
        } catch (error) {
            res.status(500).json({ error: 'Error occurred while fetching the response.' });
        }
    });

    // 로그인 라우트 (Google, Kakao, Naver 등 추가)

    const PORT = process.env.PORT || 3000;
    app.listen(PORT, () => {
        console.log(`Server is running on http://localhost:${PORT}`);
    });
}
//사용자정보조회
app.get('/api/users', async (req, res) => {
    try {
        const [users] = await db.execute('SELECT id, username, email, provider, provider_id, profile_picture FROM users');
        res.json(users);
    } catch (error) {
        console.error('Error fetching users:', error);
        res.status(500).json({ error: 'Failed to fetch users' });
    }
});



app.delete('/api/users/:id', async (req, res) => {
    const userId = req.params.id;
    try {
        await db.execute('DELETE FROM users WHERE id = ?', [userId]);
        res.json({ message: 'User deleted successfully' });
    } catch (error) {
        console.error('Error deleting user:', error);
        res.status(500).json({ error: 'Failed to delete user' });
    }
});



// 서버 시작
startServer();

