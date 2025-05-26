const bcrypt = require("bcrypt");

const password = "admin12345";  // Ganti dengan password admin yang kamu inginkan

const salt = bcrypt.genSaltSync(10);
const hashed = bcrypt.hashSync(password, salt);

console.log(hashed);
