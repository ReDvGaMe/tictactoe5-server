var express = require('express');
var router = express.Router();
var bcrypt = require('bcrypt');
var saltRounds = 10;
const { ObjectId } = require('mongodb');

var ResponseType = {
  INVALID_USERNAME: 0,
  INVALID_PASSWORD: 1,
  SUCCESS: 2,
  DUPLICATED_USERNAME: 3,
}

/* GET users listing. */
router.get('/', function (req, res, next) {
  res.send('respond with a resource');
});

// 회원가입
router.post('/signup', async function (req, res, next) {
  try {
    var username = req.body.username;
    var password = req.body.password;
    var nickname = req.body.nickname;

    // 입력값 검증
    if (!username || !password || !nickname) {
      return res.status(400).json({ message: 'All fields ar required.' });
    }

    // DB 연결
    var database = req.app.get('database');
    var users = database.collection('users');

    // 중복된 username 확인
    var existingUser = await users.findOne({ username: username });
    if (existingUser) {
      // return res.status(409).json({ message: 'Username already exists.' });
      return res.status(409).json({ result: ResponseType.DUPLICATED_USERNAME });
    }

    // 비밀번호 암호화
    var salt = bcrypt.genSaltSync(saltRounds);
    var hash = bcrypt.hashSync(password, salt);

    // DB에 사용자 정보 저장
    await users.insertOne({
      username: username,
      password: hash,
      nickname: nickname,
      createAt: new Date()
    });

    // res.status(201).json({ message: 'User registered successfully.' });
    res.status(201).json({ result: ResponseType.SUCCESS });
  }
  catch (error) {
    console.error('Error during signup: ', error);
    return res.status(500).json({ message: 'Internal server error.' });
  }
});

// 로그인
router.post('/signin', async function (req, res, next) {
  try {
    var username = req.body.username;
    var password = req.body.password;

    // 입력값 검증
    if (!username || !password) {
      return res.status(400).json({ message: 'All fields are required.' });
    }

    // DB 연결
    var database = req.app.get('database');
    var users = database.collection('users');

    // 사용자 조회
    const existingUser = await users.findOne({ username: username });
    if (existingUser) {
      var compareResult = bcrypt.compareSync(password, existingUser.password);
      if (compareResult) {
        // 세션에 사용자 정보 저장
        req.session.isAuthenticated = true;
        req.session.userId = existingUser._id.toString();
        req.session.username = existingUser.username;
        req.session.nickname = existingUser.nickname;
        // res.json({ message: 'Login successful.' });
        res.json({ result: ResponseType.SUCCESS });
      }
      else {
        // res.status(401).json({ message: 'Invalid password.' });
        res.status(401).json({ result: ResponseType.INVALID_PASSWORD });
      }
    }
    else {
      // res.status(401).json({ message: 'User not found.' });
      res.status(401).json({ result: ResponseType.INVALID_USERNAME });
    }
  }
  catch (error) {
    console.error('Error during signin: ', error);
    return res.status(500).json({ message: 'Internal server error.' });
  }
});

// 로그아웃
router.get('/signout', function (req, res, next) {
  if (req.session) {
    // 세션 삭제
    req.session.destroy(function (err) {
      if (err) {
        return res.status(500).json({ message: 'Failed to log out.' });
      } else {
        return res.json({ message: 'Logged out successfully.' });
      }
    });
  } else {
    res.json({ message: 'No active session.' });
  }
});

// 마지막 점수 업데이트
router.post('/addscore', async function (req, res, next) {
  try {
    // 세션이 존재하고 승인된 사용자가 아니면 에러
    if (!req.session.isAuthenticated) {
      return res.status(401).json({ message: 'Unauthorized' });
    }

    var userId = req.session.userId;
    var score = req.body.score;

    if (!score || isNaN(score)) {
      return res.status(400).json({ message: 'Invalid score' });
    }

    var database = req.app.get('database');
    var users = database.collection('users');

    const result = await users.updateOne(
      { _id: new ObjectId(userId), },
      {
        $set: {
          score: Number(score),
          updateAt: new Date()
        }
      }
    );

    // 데이터 베이스 상에서 유저가 없다면 에러
    if (result.matchedCount === 0) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.status(200).json({ message: 'Score updated successfully' });
  }
  catch (error) {
    console.error('Error updating score.: ', error);
    return res.status(500).json({ message: 'Internal server error.' });
  }
});

// 점수 조회
router.get('/score', async function (req, res, next) {
  try {
    // 세션이 존재하고 승인된 사용자가 아니면 에러
    if (!req.session.isAuthenticated) {
      return res.status(401).json({ message: 'Unauthorized' });
    }

    var userId = req.session.userId;

    var database = req.app.get('database');
    var users = database.collection('users');

    const user = await users.findOne({
      _id: new ObjectId(userId)
    });

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.json({
      id: user._id.toString(),
      username: user.username,
      nickname: user.nickname,
      score: user.score || 0
    });
  }
  catch (error) {
    console.error('Error fetching score.: ', error);
    return res.status(500).json({ message: 'Internal server error.' });
  }
});

module.exports = router;
