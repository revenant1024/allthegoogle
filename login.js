const express = require('express');
const passport = require('passport');
const session = require('express-session');
require('dotenv').config();
const { Strategy: GoogleStrategy } = require('passport-google-oauth20');
const { Strategy: NaverStrategy } = require('passport-naver');
const { Strategy: KakaoStrategy } = require('passport-kakao');

const app = express();

// 세션 설정
app.use(session({ secret: process.env.SESSION_SECRET, resave: false, saveUninitialized: true }));
app.use(passport.initialize());
app.use(passport.session());

// 사용자 데이터 직렬화/역직렬화
passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((obj, done) => done(null, obj));

// 구글 전략 설정
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: `${process.env.REDIRECT_URI}/google/callback`
}, (accessToken, refreshToken, profile, done) => done(null, profile)));

// 네이버 전략 설정
passport.use(new NaverStrategy({
    clientID: process.env.NAVER_CLIENT_ID,
    clientSecret: process.env.NAVER_CLIENT_SECRET,
    callbackURL: `${process.env.REDIRECT_URI}/naver/callback`
}, (accessToken, refreshToken, profile, done) => done(null, profile)));

// 카카오 전략 설정
passport.use(new KakaoStrategy({
    clientID: process.env.KAKAO_CLIENT_ID,
    callbackURL: `${process.env.REDIRECT_URI}/kakao/callback`
}, (accessToken, refreshToken, profile, done) => done(null, profile)));

// 라우트 설정
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
app.get('/auth/google/callback', passport.authenticate('google', { failureRedirect: '/' }), (req, res) => {
    res.redirect('/profile');
});

app.get('/auth/naver', passport.authenticate('naver'));
app.get('/auth/naver/callback', passport.authenticate('naver', { failureRedirect: '/' }), (req, res) => {
    res.redirect('/profile');
});

app.get('/auth/kakao', passport.authenticate('kakao'));
app.get('/auth/kakao/callback', passport.authenticate('kakao', { failureRedirect: '/' }), (req, res) => {
    res.redirect('/profile');
});

// 사용자 프로필 확인
app.get('/profile', (req, res) => {
    if (!req.isAuthenticated()) return res.redirect('/');
    res.json(req.user);
});

// 로그아웃
app.get('/logout', (req, res) => {
    req.logout(() => res.redirect('/'));
});

// 서버 시작
app.listen(3000, () => console.log('Server running on http://localhost:3000'));