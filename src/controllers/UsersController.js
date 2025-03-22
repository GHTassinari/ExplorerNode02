const { hash, compare } = require("bcryptjs")
const AppError = require ("../utils/AppError");
const sqliteConnection = require("../database/sqlite");

class UsersController {

  async create(req, res) {
    const { name, email, password } = req.body;

    const database = await sqliteConnection();

    const checkUserExists = await database.get("SELECT * FROM users WHERE email = (?)", [email])

    if(checkUserExists){
      throw new AppError ("This email is already being used");
    }

    const hashedPassword = await hash(password, 8);

    await database.run("INSERT INTO users (name, email, password) VALUES (?, ?, ?)", [name, email, hashedPassword]);

    return res.status(201).json();
  }

  async update(req, res){
    const { name, email, password, old_password } = req.body;
    const user_id = req.user.id;

    const database = await sqliteConnection();
    const user = await database.get("SELECT * FROM users WHERE id = (?)", [user_id]);

    if(!user) {
      throw new AppError("User was not found!");
    }

    const userWithUpdatedEmail = await database.get("SELECT * FROM users WHERE email = (?)", [email]);

    if(userWithUpdatedEmail && userWithUpdatedEmail.id !== user.id){
      throw new AppError("This e-mail is already being used!");
    }

    user.name = name ?? user.name; /* Now, if the name or -mail are empty, it will keep the old e-mail/name */
    user.email = email ?? user.email;

    if( password && !old_password){
      throw new AppError("You need to inform the old password in order to create a new password")
    }

    if(password && old_password){
      const checkOldPassword = await compare(old_password, user.password);

      if(!checkOldPassword) {
        throw new AppError("The old password informed, isn't equal to the account's password");
      }

      user.password = await hash(password, 8);
    }

    await database.run(`
      UPDATE users SET
      name = ?,
      email = ?,
      password = ?,
      updated_at = DATETIME('now')
      WHERE id = ?
    `, [user.name, user.email, user.password, user_id]);

    return res.status(200).json();
  }
}

module.exports = UsersController;