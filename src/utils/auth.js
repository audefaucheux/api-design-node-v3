import config from '../config'
import { User } from '../resources/user/user.model'
import jwt from 'jsonwebtoken'

export const newToken = user => {
  return jwt.sign({ id: user.id }, config.secrets.jwt, {
    expiresIn: config.secrets.jwtExp
  })
}

export const verifyToken = token =>
  new Promise((resolve, reject) => {
    jwt.verify(token, config.secrets.jwt, (err, payload) => {
      if (err) return reject(err)
      resolve(payload)
    })
  })

export const signup = async (req, res) => {
  if (!req.body.email || !req.body.password) {
    return res.status(400).send({ message: 'email and password required' })
  }

  try {
    const user = await User.create(req.body)
    const token = await newToken(user)
    return res.status(201).send({ token })
  } catch (error) {
    return res.status(400).send({ message: error })
  }
}

export const signin = async (req, res) => {
  if (!req.body.email || !req.body.password) {
    return res.status(400).send({ message: 'email and password required' })
  }
  const user = await User.findOne({ email: req.body.email }).exec()

  if (!user) {
    return res.status(401).send({ message: 'email does not exist' })
  }

  try {
    const passwordMatch = await user.checkPassword(req.body.password)
    if (!passwordMatch) {
      return res.status(401).send({ message: 'password does not match' })
    }
    const token = await newToken(user)
    return res.status(201).send({ token })
  } catch (error) {
    return res.status(401).send({ message: `${error}` })
  }
}

export const protect = async (req, res, next) => {
  if (!req.headers.authorization) {
    return res.status(401).end()
  }

  let token = req.headers.authorization.split('Bearer ')[1]

  try {
    const payload = await verifyToken(token)
    const user = await User.findById(payload.id)
      .select('-password')
      .lean()
      .exec()
    req.user = user
    next()
  } catch (error) {
    return res.status(401).end()
  }
}
