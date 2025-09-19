import jwt from "jsonwebtoken";

//creamos esta funcion para tomar el secreto del JWT desde el .env
const getSecret = (): string => {
  const secret = process.env.JWT_SECRET;
  if (!secret)
    throw new Error("JWT_SECRET is not defined in environment variables");
  return secret;
};

const generateToken = (userId: string) => {
  return jwt.sign({ id: userId }, getSecret(), { expiresIn: "1h" });
};

const verifyToken = (token: string) => {
  return jwt.verify(token, getSecret());
};

export default {
  generateToken,
  verifyToken,
};
