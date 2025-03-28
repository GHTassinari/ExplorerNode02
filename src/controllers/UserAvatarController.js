const knex = require("../database/knex");
const AppError = require("../utils/AppError");
const DiskStorage = require("../providers/DiskStorage");

class UserAvatarController {
    async update(req, res){
        const user_id = req.user.id;
        const avatarFileName = req.file.filename;

        const diskStorage = new DiskStorage();

        const user = await knex("users").where({id: user_id}).first();

        if(!user){
            throw new AppError("Only authenticated users can change their profile picture", 401);
        }

        if(user.avatar){
            await diskStorage.deleteFile(user.avatar);
        }

        const filename = await diskStorage.saveFile(avatarFileName);
        user.avatar = filename;

        await knex("users").update(user).where({ id: user_id });

        return res.json(user);
    }
}

module.exports = UserAvatarController;