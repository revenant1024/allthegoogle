const express = require('express');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 5000;

// CORS 설정
app.use(cors());
app.use(express.json());

// 간단한 API 엔드포인트 생성
app.post('/api/chat', (req, res) => {
    const { query } = req.body;
    // 여기에 OpenAI API 요청 코드나 다른 로직을 추가
    res.json({ response: `Received query: ${query}` });
});

app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
