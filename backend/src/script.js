// 1 prisma client
const { PrismaClient } = require("@prisma/client");

// 2
const prisma = new PrismaClient();

// 3 
async function main(){
    const allLinks = await prisma.link.findMany();
    console.log(allLinks);
}

// 4
main().catch(e => {
    throw e;
}).finally(async () => {
    await prisma.$disconnect();
})