const { ApolloServer } = require('apollo-server');
const fs = require('fs');
const path = require('path');
const { PrismaClient } = require('@prisma/client');
const { getUserId } = require('./utils');
const prisma = new PrismaClient();

const Query = require('./resolvers/Query');
const Mutation = require('./resolvers/Mutation');
const User = require('./resolvers/User');
const Link = require('./resolvers/Link');

// 2 implementation of schema
// identical structure to schema
const resolvers = {
    Query,
    Mutation,
    User,
    Link
}

// 3 server
const server = new ApolloServer({
    typeDefs: fs.readFileSync(
        path.join(__dirname, 'schema.graphql'), 'utf8'
    ),
    resolvers,
    context:({ req }) => {
        return {
            ...req,
            prisma,
            userId: req && req.headers.authorization ? getUserId(req) : null
        }
    }
});

server.listen().then(({ url }) => console.log(`Server is running on ${url}`));
