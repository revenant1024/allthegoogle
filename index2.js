//업로드 관련 API
// 정보 가져오기
app.get('/api/info', async (req, res) => {
    try {
        const [rows] = await db.execute('SELECT * FROM info');
        res.json(rows);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to fetch info data' });
    }
});

// 정보 추가
app.post('/api/info', async (req, res) => {
    const { title, category, content } = req.body;
    try {
        await db.execute(
            'INSERT INTO info (title, category, content) VALUES (?, ?, ?)',
            [title, category, content]
        );
        res.status(201).json({ message: 'Info added successfully' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to add info' });
    }
});

//채팅방 관련 API
// 정보 삭제
app.delete('/api/info/:id', async (req, res) => {
    const { id } = req.params;
    try {
        await db.execute('DELETE FROM info WHERE id = ?', [id]);
        res.json({ message: 'Info deleted successfully' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to delete info' });
    }
});


// 채팅방 목록 가져오기
app.get('/api/chat', async (req, res) => {
    try {
        const [rows] = await db.execute('SELECT * FROM chat');
        res.json(rows);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to fetch chat data' });
    }
});

// 채팅방 추가
app.post('/api/chat', async (req, res) => {
    const { name, participants, status } = req.body;
    try {
        await db.execute(
            'INSERT INTO chat (name, participants, status) VALUES (?, ?, ?)',
            [name, participants, status]
        );
        res.status(201).json({ message: 'Chat room added successfully' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to add chat room' });
    }
});

// 채팅방 삭제
app.delete('/api/chat/:id', async (req, res) => {
    const { id } = req.params;
    try {
        await db.execute('DELETE FROM chat WHERE id = ?', [id]);
        res.json({ message: 'Chat room deleted successfully' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to delete chat room' });
    }
});
