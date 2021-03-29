const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { APP_SECRET, getUserId } = require('../utils');

const { buildSchemaFromTypeDefinitions } = require("apollo-server");

async function post(parent, args, context, info){
    const { userId } = context;
    
    return await context.prisma.link.create({
        data: {
            url: args.url,
            description: args.description,
            postedBy: { connect: { id: userId } },
        }
    })
}

async function signup(parent, args, context, info){
    // 1 password hashing
    const password = await bcrypt.hash(args.password, 10);

    // 2 create the new user profile
    const user = await context.prisma.user.create({ data:{ ...args, password } });

    // 3 
    const token = jwt.sign({ userId: user.id }, APP_SECRET);

    // 4
    return {
        token,
        user,
    }
}

async function login(parent, args, context, info) {
    const user = await context.prisma.user.findUnique({ where: {email: args.email}});
    if (!user){
        throw new Error('User not found or password wrong');
    }

    const valid = await bcrypt.compare(args.password, user.password);
    if(!valid){
        throw new Error('User not found or password wrong');
    }

    const token = jwt.sign({ userId: user.id }, APP_SECRET);

    return {
        token, 
        user,
    }

  }

module.exports = {
    post,
    signup,
    login,
}