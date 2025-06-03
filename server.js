const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const dotenv = require('dotenv');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const http = require('http');
const { Server } = require('socket.io');
const multer = require('multer');
const path = require('path');
const winston = require('winston');
const helmet = require('helmet');
const axios = require('axios');
const { v4: uuidv4 } = require('uuid');
const Chess = require('chess.js').Chess; // Add Chess.js for server-side validation
const User = require('./models/User');
const Board = require('./models/Board');
const Thread = require('./models/Thread');
const Post = require('./models/Post');
const Report = require('./models/Report');
const auth = require('./middleware/auth');
const { validate, validateResult } = require('./middleware/validate');
const limiter = require('./middleware/rateLimit');

// Models for Live Discussion
const Room = new mongoose.Schema({
  title: { type: String, required: true },
  description: { type: String, required: true },
  creator: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  createdAt: { type: Date, default: Date.now },
});
const DiscussionRoom = mongoose.model('Room', Room);

const Comment = new mongoose.Schema({
  roomId: { type: String, required: true },
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  displayUsername: { type: String, required: true },
  content: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
});
const DiscussionComment = mongoose.model('Comment', Comment);

dotenv.config();
const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: ['https://modernforum.netlify.app'],
    methods: ['GET', 'POST'],
    credentials: true
  },
});

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: 'error.log', level: 'error' }),
    new winston.transports.File({ filename: 'combined.log' }),
  ],
});

app.use(helmet());
app.use(cors({
  origin: 'https://modernforum.netlify.app',
  credentials: true
}));
app.use(express.json());
app.use(limiter);
app.use('/uploads', (req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', 'https://modernforum.netlify.app');
  res.setHeader('Access-Control-Allow-Methods', 'GET');
  express.static(path.join(__dirname, 'Uploads'))(req, res, next);
});

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, process.env.UPLOAD_PATH);
  },
  filename: (req, file, cb) => {
    cb(null, `${Date.now()}-${file.originalname}`);
  },
});
const upload = multer({
  storage,
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) {
      cb(null, true);
    } else {
      cb(new Error('Only images are allowed'), false);
    }
  },
  limits: { fileSize: 5 * 1024 * 1024 },
});

mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => logger.info('MongoDB connected'))
  .catch(err => logger.error('MongoDB connection error:', err));

// Socket.IO Setup
const activeUsers = new Map();
const games = new Map();

// Check for a Connect Four win
const checkConnectFourWin = (board, rows = 6, cols = 7) => {
  // Horizontal
  for (let row = 0; row < rows; row++) {
    for (let col = 0; col <= cols - 4; col++) {
      const idx = row * cols + col;
      if (board[idx] && board[idx] === board[idx + 1] && board[idx] === board[idx + 2] && board[idx] === board[idx + 3]) {
        return board[idx];
      }
    }
  }
  // Vertical
  for (let row = 0; row <= rows - 4; row++) {
    for (let col = 0; col < cols; col++) {
      const idx = row * cols + col;
      if (board[idx] && board[idx] === board[idx + cols] && board[idx] === board[idx + 2 * cols] && board[idx] === board[idx + 3 * cols]) {
        return board[idx];
      }
    }
  }
  // Diagonal (positive slope)
  for (let row = 0; row <= rows - 4; row++) {
    for (let col = 0; col <= cols - 4; col++) {
      const idx = row * cols + col;
      if (board[idx] && board[idx] === board[idx + cols + 1] && board[idx] === board[idx + 2 * (cols + 1)] && board[idx] === board[idx + 3 * (cols + 1)]) {
        return board[idx];
      }
    }
  }
  // Diagonal (negative slope)
  for (let row = 3; row < rows; row++) {
    for (let col = 0; col <= cols - 4; col++) {
      const idx = row * cols + col;
      if (board[idx] && board[idx] === board[idx - cols + 1] && board[idx] === board[idx - 2 * (cols - 1)] && board[idx] === board[idx - 3 * (cols - 1)]) {
        return board[idx];
      }
    }
  }
  return null;
};

io.on('connection', (socket) => {
  logger.info(`User connected: ${socket.id}`);

  socket.on('joinThread', (threadId) => {
    socket.join(threadId);
    logger.info(`User ${socket.id} joined thread ${threadId}`);
  });

  socket.on('typing', ({ threadId, username }) => {
    socket.to(threadId).emit('typing', { username });
  });

  socket.on('stopTyping', ({ threadId }) => {
    socket.to(threadId).emit('stopTyping');
  });

  socket.on('joinRoom', ({ roomId, userId }) => {
    socket.join(roomId);
    if (!activeUsers.has(roomId)) {
      activeUsers.set(roomId, new Set());
    }
    activeUsers.get(roomId).add(socket.id);
    io.to(roomId).emit('activeUsers', activeUsers.get(roomId).size);
    logger.info(`Socket ${socket.id} (User ${userId}) joined room ${roomId}. Active users: ${activeUsers.get(roomId).size}`);
  });

  socket.on('leaveRoom', ({ roomId, userId }) => {
    if (activeUsers.has(roomId)) {
      activeUsers.get(roomId).delete(socket.id);
      io.to(roomId).emit('activeUsers', activeUsers.get(roomId).size || 0);
      if (activeUsers.get(roomId).size === 0) {
        activeUsers.delete(roomId);
      }
      logger.info(`Socket ${socket.id} (User ${userId}) left room ${roomId}. Active users: ${activeUsers.get(roomId)?.size || 0}`);
    }
    socket.leave(roomId);
  });

  socket.on('newComment', async ({ roomId, userId, content, displayUsername }) => {
    try {
      logger.info(`Received newComment for room ${roomId} by ${displayUsername}: ${content}`);
      const comment = new DiscussionComment({
        roomId,
        user: userId,
        displayUsername,
        content,
      });
      await comment.save();
      logger.info(`Comment saved for room ${roomId}: ${comment._id}`);
      io.to(roomId).emit('newComment', comment);
      logger.info(`Emitted newComment to room ${roomId}`);
    } catch (err) {
      logger.error('Comment save error:', err);
    }
  });

  // Game-related Socket.IO events
  socket.on('createRoom', ({ gameType, displayUsername }) => {
    const roomCode = uuidv4().slice(0, 6).toUpperCase();
    let initialGameState;
    if (gameType === 'tic-tac-toe') {
      initialGameState = {
        gameType,
        board: Array(9).fill(''),
        currentTurn: 'X',
        players: [{ id: socket.id, symbol: 'X', displayUsername }],
        winner: null,
      };
    } else if (gameType === 'connect-four') {
      initialGameState = {
        gameType,
        board: Array(42).fill(''),
        currentTurn: 'R',
        players: [{ id: socket.id, symbol: 'R', displayUsername }],
        winner: null,
      };
    } else if (gameType === 'road-rash') {
      initialGameState = {
        gameType,
        players: [{
          id: socket.id,
          displayUsername,
          x: 50,
          y: 300,
          speed: 0,
          health: 100,
          direction: 0,
        }],
        winner: null,
        raceFinished: false,
        trackLength: 5000,
      };
    } else if (gameType === 'chess') {
      const chess = new Chess();
      initialGameState = {
        gameType,
        fen: chess.fen(),
        currentTurn: 'w', // White to move
        players: [{ id: socket.id, color: 'w', displayUsername }],
        winner: null,
        history: [], // Store moves for PGN generation
        result: '*', // Game result (e.g., "1-0", "0-1", "1/2-1/2", "*")
      };
    } else {
      socket.emit('error', 'Invalid game type.');
      return;
    }
    games.set(roomCode, initialGameState);
    socket.join(roomCode);
    socket.emit('roomCreated', { roomCode, playerSymbol: gameType === 'road-rash' || gameType === 'chess' ? null : initialGameState.players[0].symbol });
    logger.info(`Game room created: ${roomCode} for ${gameType}`);
  });

  socket.on('joinRoom', ({ roomCode, displayUsername }) => {
    const game = games.get(roomCode);
    if (!game) {
      socket.emit('error', 'Room not found.');
      return;
    }
    if (game.players.length >= 2) {
      socket.emit('error', 'Room is full.');
      return;
    }
    let playerData;
    if (game.gameType === 'tic-tac-toe') {
      playerData = { id: socket.id, symbol: 'O', displayUsername };
    } else if (game.gameType === 'connect-four') {
      playerData = { id: socket.id, symbol: 'Y', displayUsername };
    } else if (game.gameType === 'road-rash') {
      playerData = {
        id: socket.id,
        displayUsername,
        x: 50,
        y: 350,
        speed: 0,
        health: 100,
        direction: 0,
      };
    } else if (game.gameType === 'chess') {
      playerData = { id: socket.id, color: 'b', displayUsername };
    }
    game.players.push(playerData);
    socket.join(roomCode);
    socket.emit('joinedRoom', { roomCode, playerSymbol: game.gameType === 'road-rash' || game.gameType === 'chess' ? null : playerData.symbol, gameState: game });
    io.to(roomCode).emit('gameUpdate', game);
    logger.info(`User ${displayUsername} joined game room: ${roomCode} for ${game.gameType}`);
  });

  socket.on('makeMove', ({ gameType, roomCode, position, move }) => {
    const game = games.get(roomCode);
    if (!game) {
      socket.emit('error', 'Room not found.');
      return;
    }

    if (game.gameType === 'tic-tac-toe') {
      if (game.currentTurn !== game.players.find(p => p.id === socket.id).symbol) {
        socket.emit('error', 'Not your turn.');
        return;
      }
      if (game.board[position] !== '') {
        socket.emit('error', 'Cell already taken.');
        return;
      }
      game.board[position] = game.currentTurn;
      game.currentTurn = game.currentTurn === 'X' ? 'O' : 'X';

      const winningCombinations = [
        [0, 1, 2], [3, 4, 5], [6, 7, 8],
        [0, 3, 6], [1, 4, 7], [2, 5, 8],
        [0, 4, 8], [2, 4, 6],
      ];
      for (const combo of winningCombinations) {
        const [a, b, c] = combo;
        if (game.board[a] && game.board[a] === game.board[b] && game.board[a] === game.board[c]) {
          game.winner = game.board[a];
          break;
        }
      }
      if (!game.winner && game.board.every(cell => cell !== '')) {
        game.winner = 'Draw';
      }
    } else if (game.gameType === 'connect-four') {
      const col = position;
      let row = -1;
      for (let r = 0; r < 6; r++) {
        const idx = r * 7 + col;
        if (game.board[idx] === '') {
          row = r;
          break;
        }
      }
      if (row === -1) {
        socket.emit('error', 'Column is full.');
        return;
      }
      const idx = row * 7 + col;
      game.board[idx] = game.currentTurn;
      game.currentTurn = game.currentTurn === 'R' ? 'Y' : 'R';

      const winner = checkConnectFourWin(game.board);
      if (winner) {
        game.winner = winner;
      } else if (game.board.every(cell => cell !== '')) {
        game.winner = 'Draw';
      }
    } else if (game.gameType === 'chess') {
      const player = game.players.find(p => p.id === socket.id);
      if (!player) {
        socket.emit('error', 'Player not found.');
        return;
      }
      if (game.currentTurn !== player.color) {
        socket.emit('error', 'Not your turn.');
        return;
      }

      const chess = new Chess(game.fen);
      const moveResult = chess.move(move);
      if (!moveResult) {
        socket.emit('error', 'Invalid move.');
        return;
      }

      game.fen = chess.fen();
      game.currentTurn = chess.turn();
      game.history.push(moveResult.san);

      if (chess.isGameOver()) {
        if (chess.isCheckmate()) {
          game.winner = player.color === 'w' ? 'White' : 'Black';
          game.result = player.color === 'w' ? '1-0' : '0-1';
        } else if (chess.isDraw()) {
          game.winner = 'Draw';
          game.result = '1/2-1/2';
        }
      }

      // Generate PGN if the game is over
      if (game.winner) {
        const chessForPgn = new Chess();
        game.history.forEach(move => chessForPgn.move(move));
        const pgn = chessForPgn.pgn({
          newline_char: '\n',
          Event: 'Live Chess',
          Site: 'YourApp',
          Date: new Date().toISOString().split('T')[0],
          Round: '?',
          White: game.players.find(p => p.color === 'w').displayUsername,
          Black: game.players.find(p => p.color === 'b').displayUsername,
          Result: game.result,
          TimeControl: 'none',
        });
        game.pgn = pgn;
      }
    } else {
      socket.emit('error', 'Invalid game type for move.');
      return;
    }

    io.to(roomCode).emit('gameUpdate', game);
    logger.info(`Move made in game room ${roomCode} for ${gameType}: ${move || position}`);
  });

  // Chess-specific event: Resign
  socket.on('resign', ({ roomCode }) => {
    const game = games.get(roomCode);
    if (!game || game.gameType !== 'chess') {
      socket.emit('error', 'Room not found or invalid game type.');
      return;
    }
    const player = game.players.find(p => p.id === socket.id);
    if (!player) {
      socket.emit('error', 'Player not found.');
      return;
    }
    game.winner = player.color === 'w' ? 'Black' : 'White';
    game.result = player.color === 'w' ? '0-1' : '1-0';

    // Generate PGN
    const chess = new Chess();
    game.history.forEach(move => chess.move(move));
    const pgn = chess.pgn({
      newline_char: '\n',
      Event: 'Live Chess',
      Site: 'YourApp',
      Date: new Date().toISOString().split('T')[0],
      Round: '?',
      White: game.players.find(p => p.color === 'w').displayUsername,
      Black: game.players.find(p => p.color === 'b').displayUsername,
      Result: game.result,
      TimeControl: 'none',
      Termination: `${player.displayUsername} resigned`,
    });
    game.pgn = pgn;

    io.to(roomCode).emit('gameUpdate', game);
    logger.info(`Player ${player.displayUsername} resigned in game room ${roomCode}`);
  });

  // Road Rash game-specific events
  socket.on('updatePosition', ({ roomCode, x, y, speed, direction }) => {
    const game = games.get(roomCode);
    if (!game || game.gameType !== 'road-rash') {
      socket.emit('error', 'Room not found or invalid game type.');
      return;
    }
    const player = game.players.find(p => p.id === socket.id);
    if (!player) {
      socket.emit('error', 'Player not found.');
      return;
    }
    player.x = x;
    player.y = y;
    player.speed = speed;
    player.direction = direction;

    if (player.x >= game.trackLength && !game.raceFinished) {
      game.winner = player.displayUsername;
      game.raceFinished = true;
      io.to(roomCode).emit('raceFinished', { winner: game.winner });
    }

    io.to(roomCode).emit('gameUpdate', game);
  });

  socket.on('attack', ({ roomCode, targetId }) => {
    const game = games.get(roomCode);
    if (!game || game.gameType !== 'road-rash') {
      socket.emit('error', 'Room not found or invalid game type.');
      return;
    }
    const attacker = game.players.find(p => p.id === socket.id);
    const target = game.players.find(p => p.id === targetId);
    if (!attacker || !target) {
      socket.emit('error', 'Player or target not found.');
      return;
    }

    const distance = Math.sqrt(Math.pow(attacker.x - target.x, 2) + Math.pow(attacker.y - target.y, 2));
    if (distance > 50) {
      socket.emit('error', 'Target is too far to attack.');
      return;
    }

    target.health -= 20;
    if (target.health <= 0) {
      target.health = 0;
      target.speed = 0;
      const activePlayers = game.players.filter(p => p.health > 0);
      if (activePlayers.length === 1 && !game.raceFinished) {
        game.winner = activePlayers[0].displayUsername;
        game.raceFinished = true;
        io.to(roomCode).emit('raceFinished', { winner: game.winner });
      }
    }

    io.to(roomCode).emit('gameUpdate', game);
    logger.info(`Attack in game room ${roomCode}: ${attacker.displayUsername} attacked ${target.displayUsername}`);
  });

  socket.on('resetGame', ({ gameType, roomCode }) => {
    const game = games.get(roomCode);
    if (!game) {
      socket.emit('error', 'Room not found.');
      return;
    }
    if (gameType === 'tic-tac-toe') {
      game.board = Array(9).fill('');
      game.currentTurn = 'X';
      game.winner = null;
    } else if (gameType === 'connect-four') {
      game.board = Array(42).fill('');
      game.currentTurn = 'R';
      game.winner = null;
    } else if (gameType === 'road-rash') {
      game.players.forEach(player => {
        player.x = 50;
        player.y = player.y === 300 ? 300 : 350;
        player.speed = 0;
        player.health = 100;
        player.direction = 0;
      });
      game.winner = null;
      game.raceFinished = false;
    } else if (gameType === 'chess') {
      const chess = new Chess();
      game.fen = chess.fen();
      game.currentTurn = 'w';
      game.winner = null;
      game.history = [];
      game.result = '*';
      game.pgn = null;
    }
    io.to(roomCode).emit('gameUpdate', game);
    logger.info(`Game reset in room ${roomCode} for ${gameType}`);
  });

  socket.on('disconnect', () => {
    activeUsers.forEach((users, roomId) => {
      if (users.has(socket.id)) {
        users.delete(socket.id);
        io.to(roomId).emit('activeUsers', users.size);
        if (users.size === 0) {
          activeUsers.delete(roomId);
        }
        logger.info(`Socket ${socket.id} disconnected from discussion room ${roomId}. Active users: ${users.size}`);
      }
    });

    for (const [roomCode, game] of games.entries()) {
      const playerIndex = game.players.findIndex(p => p.id === socket.id);
      if (playerIndex !== -1) {
        game.players.splice(playerIndex, 1);
        if (game.players.length === 0) {
          games.delete(roomCode);
          logger.info(`Game room deleted: ${roomCode}`);
        } else {
          io.to(roomCode).emit('error', 'A player disconnected. Please create or join a new room.');
          logger.info(`Player disconnected from game room ${roomCode}. Remaining players: ${game.players.length}`);
        }
        break;
      }
    }

    logger.info(`User disconnected: ${socket.id}`);
  });
});

// Authentication Routes
app.post('/api/auth/register', validate.user, validateResult, async (req, res) => {
  try {
    const { username, password } = req.body;
    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.status(400).json({ error: 'Username already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ username, password: hashedPassword });
    await user.save();

    logger.info(`User registered: ${username}`);
    res.status(201).json({ message: 'User registered successfully' });
  } catch (err) {
    logger.error('Register error:', err);
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/auth/login', validate.user, validateResult, async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign({ userId: user._id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1h' });
    logger.info(`User logged in: ${username}`);
    res.json({ token });
  } catch (err) {
    logger.error('Login error:', err);
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/auth/me', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).select('username role moderatorBoards');
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json({ username: user.username, role: user.role, moderatorBoards: user.moderatorBoards });
  } catch (err) {
    logger.error('Auth me error:', err);
    res.status(500).json({ error: err.message });
  }
});

// Board Routes
app.post('/api/boards', auth, validate.board, validateResult, async (req, res) => {
  try {
    if (!req.user || req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }
    const { name, description } = req.body;
    const board = new Board({ name, description });
    await board.save();

    logger.info(`Board created: ${name}`);
    res.status(201).json(board);
  } catch (err) {
    logger.error('Board creation error:', err);
    res.status(400).json({ error: err.message });
  }
});

app.get('/api/boards', validate.pagination, validateResult, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    const boards = await Board.find().skip(skip).limit(limit);
    const total = await Board.countDocuments();

    res.json({
      boards,
      pagination: { page, limit, total, pages: Math.ceil(total / limit) },
    });
  } catch (err) {
    logger.error('Board list error:', err);
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/boards/:boardId', async (req, res) => {
  try {
    const board = await Board.findById(req.params.boardId);
    if (!board) {
      return res.status(404).json({ error: 'Board not found' });
    }
    res.json(board);
  } catch (err) {
    logger.error('Board fetch error:', err);
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/boards/:boardId/moderators', auth, validate.assignModerator, validateResult, async (req, res) => {
  try {
    if (!req.user || req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }

    const { userId } = req.body;
    const board = await Board.findById(req.params.boardId);
    if (!board) {
      return res.status(404).json({ error: 'Board not found' });
    }

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    user.role = 'moderator';
    user.moderatorBoards.push(req.params.boardId);
    await user.save();

    logger.info(`Moderator assigned: ${user.username} to board ${board.name}`);
    res.json({ message: 'Moderator assigned successfully' });
  } catch (err) {
    logger.error('Moderator assignment error:', err);
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/boards/:boardId/moderators/:userId', auth, validate.assignModerator, validateResult, async (req, res) => {
  try {
    if (!req.user || req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }

    const board = await Board.findById(req.params.boardId);
    if (!board) {
      return res.status(404).json({ error: 'Board not found' });
    }

    const user = await User.findById(req.params.userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    user.moderatorBoards = user.moderatorBoards.filter(
      boardId => boardId.toString() !== req.params.boardId
    );
    if (user.moderatorBoards.length === 0 && user.role === 'moderator') {
      user.role = 'user';
    }
    await user.save();

    logger.info(`Moderator removed: ${user.username} from board ${board.name}`);
    res.json({ message: 'Moderator removed successfully' });
  } catch (err) {
    logger.error('Moderator removal error:', err);
    res.status(500).json({ error: err.message });
  }
});

// Thread Routes
app.post('/api/boards/:boardId/threads', [auth, upload.single('media'), validate.thread, validateResult], async (req, res) => {
  try {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required to create threads' });
    }
    const { title, content } = req.body;
    const anonymous = req.body.anonymous === false || req.body.anonymous === 'false' ? false : true;
    const board = await Board.findById(req.params.boardId);
    if (!board) {
      return res.status(404).json({ error: 'Board not found' });
    }

    const thread = new Thread({ title, board: req.params.boardId });
    await thread.save();

    const user = await User.findById(req.user.userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const displayUsername = anonymous ? `Anon${Math.floor(Math.random() * 10000)}` : user.username;
    const userId = anonymous ? null : user._id;

    const post = new Post({
      content,
      thread: thread._id,
      user: userId,
      displayUsername,
      media: req.file ? `/uploads/${req.file.filename}` : null,
    });
    await post.save();

    thread.posts.push(post._id);
    await thread.save();

    logger.info(`Emitting newPost for post ${post._id} in thread ${thread._id}`);
    io.to(thread._id.toString()).emit('newPost', post);
    logger.info(`Thread created: ${title} by ${displayUsername}`);
    res.status(201).json(thread);
  } catch (err) {
    logger.error('Thread creation error:', err);
    res.status(400).json({ error: err.message });
  }
});

app.get('/api/boards/:boardId/threads', validate.pagination, validateResult, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    const threads = await Thread.find({ board: req.params.boardId })
      .populate('posts')
      .skip(skip)
      .limit(limit);
    const total = await Thread.countDocuments({ board: req.params.boardId });

    res.json({
      threads,
      pagination: { page, limit, total, pages: Math.ceil(total / limit) },
    });
  } catch (err) {
    logger.error('Thread list error:', err);
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/threads/:threadId', async (req, res) => {
  try {
    const thread = await Thread.findById(req.params.threadId).populate({
      path: 'posts',
      populate: { path: 'parentPost', select: 'displayUsername' }
    });
    if (!thread) {
      return res.status(404).json({ error: 'Thread not found' });
    }
    res.json(thread);
  } catch (err) {
    logger.error('Thread fetch error:', err);
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/threads/:threadId/posts', [auth, upload.single('media'), validate.post, validateResult], async (req, res) => {
  try {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required to create posts' });
    }
    const { content, parentPost } = req.body;
    const anonymous = req.body.anonymous === false || req.body.anonymous === 'false' ? false : true;
    const thread = await Thread.findById(req.params.threadId);
    if (!thread) {
      return res.status(404).json({ error: 'Thread not found' });
    }

    if (parentPost) {
      const parent = await Post.findById(parentPost);
      if (!parent || parent.thread.toString() !== req.params.threadId) {
        return res.status(404).json({ error: 'Parent post not found or invalid' });
      }
    }

    const user = await User.findById(req.user.userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const displayUsername = anonymous ? `Anon${Math.floor(Math.random() * 10000)}` : user.username;
    const userId = anonymous ? null : user._id;

    const post = new Post({
      content,
      thread: req.params.threadId,
      user: userId,
      displayUsername,
      media: req.file ? `/uploads/${req.file.filename}` : null,
      parentPost: parentPost || null,
    });
    await post.save();

    thread.posts.push(post._id);
    await thread.save();

    const populatedPost = await Post.findById(post._id).populate('parentPost', 'displayUsername');

    logger.info(`Emitting ${parentPost ? 'newReply' : 'newPost'} for post ${post._id} in thread ${thread._id}`);
    io.to(req.params.threadId).emit(parentPost ? 'newReply' : 'newPost', populatedPost);
    logger.info(`Post created by ${displayUsername} in thread ${thread._id}`);
    res.status(201).json(populatedPost);
  } catch (err) {
    logger.error('Post creation error:', err);
    res.status(400).json({ error: err.message });
  }
});

// Post Interaction Routes
app.post('/api/posts/:postId/react', auth, async (req, res) => {
  try {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required' });
    }
    const { type } = req.body;
    if (!['heart', 'like', 'happy', 'laugh', 'angry'].includes(type)) {
      return res.status(400).json({ error: 'Invalid reaction type' });
    }

    const post = await Post.findById(req.params.postId);
    if (!post) {
      return res.status(404).json({ error: 'Post not found' });
    }

    const existingReaction = post.reactions.find(
      (r) => r.user.toString() === req.user.userId
    );
    if (existingReaction) {
      if (existingReaction.type === type) {
        post.reactions = post.reactions.filter(
          (r) => r.user.toString() !== req.user.userId
        );
      } else {
        existingReaction.type = type;
      }
    } else {
      post.reactions.push({ user: req.user.userId, type });
    }
    await post.save();

    logger.info(`Emitting reactionAdded for post ${post._id}`);
    io.to(post.thread.toString()).emit('reactionAdded', { postId: post._id, reactions: post.reactions });
    logger.info(`Reaction ${type} added to post ${post._id} by user ${req.user.userId}`);
    res.json(post.reactions);
  } catch (err) {
    logger.error('Reaction error:', err);
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/posts/:postId/vote', auth, async (req, res) => {
  try {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required' });
    }
    const { vote } = req.body;
    if (!['up', 'down'].includes(vote)) {
      return res.status(400).json({ error: 'Invalid vote type' });
    }

    const post = await Post.findById(req.params.postId);
    if (!post) {
      return res.status(404).json({ error: 'Post not found' });
    }

    const userId = req.user.userId;
    const hasUpvoted = post.upvotes.includes(userId);
    const hasDownvoted = post.downvotes.includes(userId);

    if (vote === 'up') {
      if (hasUpvoted) {
        post.upvotes = post.upvotes.filter((id) => id.toString() !== userId);
      } else {
        post.upvotes.push(userId);
        if (hasDownvoted) {
          post.downvotes = post.downvotes.filter((id) => id.toString() !== userId);
        }
      }
    } else if (vote === 'down') {
      if (hasDownvoted) {
        post.downvotes = post.downvotes.filter((id) => id.toString() !== userId);
      } else {
        post.downvotes.push(userId);
        if (hasUpvoted) {
          post.upvotes = post.upvotes.filter((id) => id.toString() !== userId);
        }
      }
    }

    await post.save();

    logger.info(`Emitting voteUpdated for post ${post._id}`);
    io.to(post.thread.toString()).emit('voteUpdated', {
      postId: post._id,
      upvotes: post.upvotes,
      downvotes: post.downvotes,
    });
    logger.info(`Vote ${vote} on post ${post._id} by user ${userId}`);
    res.json({ upvotes: post.upvotes, downvotes: post.downvotes });
  } catch (err) {
    logger.error('Vote error:', err);
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/posts/:postId/star', auth, async (req, res) => {
  try {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    const post = await Post.findById(req.params.postId);
    if (!post) {
      return res.status(404).json({ error: 'Post not found' });
    }

    const userId = req.user.userId;
    const isStarred = post.starredBy.includes(userId);

    if (isStarred) {
      post.starredBy = post.starredBy.filter((id) => id.toString() !== userId);
    } else {
      post.starredBy.push(userId);
    }
    await post.save();

    logger.info(`Emitting starToggled for post ${post._id}`);
    io.to(post.thread.toString()).emit('starToggled', {
      postId: post._id,
      userId,
      starred: !isStarred,
    });
    logger.info(`Star ${isStarred ? 'removed' : 'added'} on post ${post._id} by user ${userId}`);
    res.json({ starred: !isStarred });
  } catch (err) {
    logger.error('Star error:', err);
    res.status(500).json({ error: err.message });
  }
});

// Moderation Routes
app.delete('/api/posts/:postId', auth, validate.deletePost, validateResult, async (req, res) => {
  try {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required' });
    }
    const post = await Post.findById(req.params.postId).populate('thread');
    if (!post) {
      return res.status(404).json({ error: 'Post not found' });
    }

    const user = await User.findById(req.user.userId);
    if (
      req.user.role !== 'admin' &&
      !(req.user.role === 'moderator' && user.moderatorBoards.includes(post.thread.board.toString()))
    ) {
      return res.status(403).json({ error: 'Unauthorized to delete post' });
    }

    await Post.deleteOne({ _id: req.params.postId });
    await Thread.updateOne({ _id: post.thread._id }, { $pull: { posts: req.params.postId } });

    logger.info(`Emitting postDeleted for post ${post._id} in thread ${post.thread._id}`);
    io.to(post.thread._id.toString()).emit('postDeleted', req.params.postId);
    logger.info(`Post deleted: ${post._id}`);
    res.json({ message: 'Post deleted successfully' });
  } catch (err) {
    logger.error('Post deletion error:', err);
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/posts/:postId/report', auth, validate.report, validateResult, async (req, res) => {
  try {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required' });
    }
    const { reason } = req.body;
    const post = await Post.findById(req.params.postId);
    if (!post) {
      return res.status(404).json({ error: 'Post not found' });
    }

    const report = new Report({
      post: req.params.postId,
      user: req.user.userId,
      reason,
    });
    await report.save();

    logger.info(`Post reported: ${post._id}`);
    res.status(201).json({ message: 'Post reported successfully' });
  } catch (err) {
    logger.error('Report error:', err);
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/boards/:boardId/reports', auth, validate.pagination, validateResult, async (req, res) => {
  try {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required' });
    }
    const user = await User.findById(req.user.userId);
    if (
      req.user.role !== 'admin' &&
      !(req.user.role === 'moderator' && user.moderatorBoards.includes(req.params.boardId))
    ) {
      return res.status(403).json({ error: 'Unauthorized to view reports' });
    }

    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    const threadIds = await Thread.find({ board: req.params.boardId }).distinct('_id');
    const reports = await Report.find({ post: { $in: await Post.find({ thread: { $in: threadIds } }).distinct('_id') } })
      .populate('post')
      .skip(skip)
      .limit(limit);
    const total = await Report.countDocuments({ post: { $in: await Post.find({ thread: { $in: threadIds } }).distinct('_id') } });

    res.json({
      reports,
      pagination: { page, limit, total, pages: Math.ceil(total / limit) },
    });
  } catch (err) {
    logger.error('Report list error:', err);
    res.status(500).json({ error: err.message });
  }
});

// Admin Routes
app.get('/api/users', auth, validate.pagination, validateResult, async (req, res) => {
  try {
    if (!req.user || req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }

    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    const users = await User.find().select('username role moderatorBoards')
      .skip(skip)
      .limit(limit);
    const total = await User.countDocuments();

    res.json({
      users,
      pagination: { page, limit, total, pages: Math.ceil(total / limit) },
    });
  } catch (err) {
    logger.error('User list error:', err);
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/users/:userId', auth, async (req, res) => {
  try {
    if (!req.user || req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }

    const user = await User.findById(req.params.userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    if (user.role === 'admin') {
      return res.status(403).json({ error: 'Cannot delete an admin user' });
    }

    await User.deleteOne({ _id: req.params.userId });
    await Post.deleteMany({ user: req.params.userId });
    await Thread.updateMany({}, { $pull: { posts: { user: req.params.userId } } });

    logger.info(`User deleted: ${user.username}`);
    res.json({ message: 'User deleted successfully' });
  } catch (err) {
    logger.error('User deletion error:', err);
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/boards/:boardId', auth, async (req, res) => {
  try {
    if (!req.user || req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }

    const board = await Board.findById(req.params.boardId);
    if (!board) {
      return res.status(404).json({ error: 'Board not found' });
    }

    const threads = await Thread.find({ board: req.params.boardId });
    const threadIds = threads.map(thread => thread._id);
    await Post.deleteMany({ thread: { $in: threadIds } });
    await Thread.deleteMany({ board: req.params.boardId });
    await Board.deleteOne({ _id: req.params.boardId });

    logger.info(`Board deleted: ${board.name}`);
    res.json({ message: 'Board deleted successfully' });
  } catch (err) {
    logger.error('Board deletion error:', err);
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/threads/:threadId', auth, async (req, res) => {
  try {
    if (!req.user || req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }

    const thread = await Thread.findById(req.params.threadId);
    if (!thread) {
      return res.status(404).json({ error: 'Thread not found' });
    }

    await Post.deleteMany({ thread: req.params.threadId });
    await Thread.deleteOne({ _id: req.params.threadId });

    logger.info(`Thread deleted: ${thread.title}`);
    res.json({ message: 'Thread deleted successfully' });
  } catch (err) {
    logger.error('Thread deletion error:', err);
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/threads', auth, validate.pagination, validateResult, async (req, res) => {
  try {
    if (!req.user || req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }

    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    const threads = await Thread.find()
      .populate('board', 'name')
      .skip(skip)
      .limit(limit);
    const total = await Thread.countDocuments();

    res.json({
      threads,
      pagination: { page, limit, total, pages: Math.ceil(total / limit) },
    });
  } catch (err) {
    logger.error('Thread list error:', err);
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/posts', auth, validate.pagination, validateResult, async (req, res) => {
  try {
    if (!req.user || req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }

    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    const posts = await Post.find()
      .populate('thread', 'title')
      .skip(skip)
      .limit(limit);
    const total = await Post.countDocuments();

    res.json({
      posts,
      pagination: { page, limit, total, pages: Math.ceil(total / limit) },
    });
  } catch (err) {
    logger.error('Post list error:', err);
    res.status(500).json({ error: err.message });
  }
});

// Live Discussion Routes
app.get('/api/news/:category', async (req, res) => {
  try {
    const category = req.params.category;
    const validCategories = ['technology', 'sports', 'general'];
    if (!validCategories.includes(category)) {
      return res.status(400).json({ error: 'Invalid category' });
    }

    const response = await axios.get(`https://newsapi.org/v2/top-headlines`, {
      params: {
        category,
        apiKey: process.env.NEWS_API_KEY,
        pageSize: 5,
      },
    });

    res.json(response.data.articles);
  } catch (err) {
    logger.error('News fetch error:', err);
    res.status(500).json({ error: 'Failed to fetch news' });
  }
});

app.post('/api/rooms', auth, async (req, res) => {
  try {
    const { title, description } = req.body;
    if (!title || !description) {
      return res.status(400).json({ error: 'Title and description are required' });
    }

    const room = new DiscussionRoom({
      title,
      description,
      creator: req.user.userId,
    });
    await room.save();

    logger.info(`Custom room created: ${title}`);
    res.status(201).json(room);
  } catch (err) {
    logger.error('Room creation error:', err);
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/rooms', async (req, res) => {
  try {
    const rooms = await DiscussionRoom.find().populate('creator', 'username');
    res.json(rooms);
  } catch (err) {
    logger.error('Room fetch error:', err);
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/comments/:roomId', async (req, res) => {
  try {
    const roomId = decodeURIComponent(req.params.roomId);
    logger.info(`Fetching comments for roomId: ${roomId}`);
    const comments = await DiscussionComment.find({ roomId })
      .populate('user', 'username');
    res.json(comments);
  } catch (err) {
    logger.error('Comment fetch error:', err);
    res.status(500).json({ error: 'Failed to fetch comments' });
  }
});

const PORT = process.env.PORT || 5001;
server.listen(PORT, () => logger.info(`Server running on port ${PORT}`));