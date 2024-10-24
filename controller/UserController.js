const conn = require('../mariadb');
const {StatusCodes} = require('http-status-codes');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
const crypto = require('crypto');

dotenv.config();

const signup = (req, res) => {
    const {username, password, nickname} = req.body;

    const salt = crypto.randomBytes(10).toString('base64');
    const hashPassword = crypto.pbkdf2Sync(password, salt, 10000, 10, 'sha512').toString('base64');

    let sql = 'INSERT INTO users (username, password, nickname, salt) VALUES (?,?,?,?)';
    let values = [username,hashPassword,nickname, salt];

    conn.query(sql, values,
        function (err, results) {
            if(err){
                console.log(err);
                return res.status(StatusCodes.BAD_REQUEST).end();
            }

            console.log(results);

            res.status(StatusCodes.CREATED).json({
                username : username,
                nickname : nickname,
                authorities : [
                    {
                        authorityName : "ROLE_USER"
                    }
                ]
            });
        }
    );
};

const signin = (req, res) => {
    const {username, password} = req.body

    let sql = `SELECT * FROM users WHERE username = ?`

    conn.query(sql, username,
        function (err, results) {
            if(err){
                console.log(err)
                return res.status(StatusCodes.BAD_REQUEST).end()
            }

            let loginUser = results[0]

            const hashPassword = crypto.pbkdf2Sync(password, loginUser.salt, 10000, 10, 'sha512').toString('base64');

            if(loginUser && loginUser.password == hashPassword){
                const token = jwt.sign({ 
                    username : loginUser.username,
                    nickname : loginUser.nickname 
                }, process.env.PRIVATE_KEY,{
                    expiresIn : '20m',
                    issuer : "heebeom"
                });

                res.status(StatusCodes.OK).json({
                        message : `${loginUser.nickname}님 로그인 되었습니다.`,
                        token : token
                })
            }
            else{
                res.status(StatusCodes.FORBIDDEN).json({
                    message : `이메일 또는 비밀번호가 틀렸습니다.`
                })
            }
                
        }
    )
};

const passwordResetRequest = (req, res)=>{
    const {username} = req.body;

    let sql = 'SELECT * FROM users WHERE username = ?';

    conn.query(sql, username,
        (err, results) => {
            if(err){
                console.log(err);
                return res.status(StatusCodes.BAD_REQUEST).end();
            }

            const user = results[0];
            if(user){
                return res.status(StatusCodes.OK).json({
                    userName : username
                });
            }else{
                return res.status(StatusCodes.UNAUTHORIZED).end();
            }
        }
    )
};

const passwordReset = (req, res)=>{
    const {username, password} = req.body;

    const salt = crypto.randomBytes(10).toString('base64');
    const hashPassword = crypto.pbkdf2Sync(password, salt, 10000, 10, 'sha512').toString('base64');

    let sql = 'UPDATE users SET password = ?, salt = ? WHERE username = ?';
    let values = [hashPassword, salt, username];

    conn.query(sql, values,
        (err, results) => {
            if(err){
                console.log(err);
                return res.status(StatusCodes.BAD_REQUEST).end();
            }
            if(results.affectedRows == 0)
                return res.status(StatusCodes.BAD_REQUEST).end();
            else
                return res.status(StatusCodes.OK).json(results);
        }
    )

};

const deleteUser = (req, res)=>{
    let {username} = req.body
    
    let sql = `DELETE FROM users WHERE username = ?`
    conn.query(sql,username,
        function (err, results) {
            if(err){
                console.log(err)
                return res.status(400).end()
            }

            if(results.affectedRows == 0){
                res.status(400).end()
            }else{
                res.status(200).json(results)
            }
        }
    )
}

module.exports = {
    signup,
    signin,
    passwordResetRequest,
    passwordReset,
    deleteUser
};