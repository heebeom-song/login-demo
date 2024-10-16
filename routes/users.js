const express = require('express');
const router = express.Router();
const {body, validationResult} = require("express-validator");
const { sign, signup } = require('../controller/UserController');
const {StatusCodes} = require('http-status-codes');

router.use(express.json());

const validate = (req, res, next) => {
    const err = validationResult(req);

    if(err.isEmpty()){
        return next();
    }else{
        return res.status(StatusCodes.BAD_REQUEST).json(err.array()); // 에러 없으면 다음 할일(함수나 미들웨어) 찾아가라! 
    }
};

//로그인
router.post(
    '/sign', 
    [
        body('username').notEmpty().isString().withMessage('이름 확인 필요'),
        body('password').notEmpty().isString().withMessage('비밀번호 확인 필요'),
        validate
    ],
    sign
)

//회원가입
router.post(
    '/signup',
    [
        body('username').notEmpty().isString().withMessage('이름 확인 필요'),
        body('nickname').notEmpty().isString().withMessage('닉네임 확인 필요'),
        body('password').notEmpty().isString().withMessage('비밀번호 확인 필요'),
        validate
    ], 
    signup
)

module.exports = router