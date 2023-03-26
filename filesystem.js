let fs = require('fs');
let tasksFolder = './tasks/';
let usersFolder = './users/credentials'


function write(obj, path) {
    let json = JSON.stringify(obj);
    fs.writeFileSync(path, json, function (err) {
        if (err)
            console.log(err);
    });
}

function read(path) {
    return JSON.parse(fs.readFileSync(path, 'utf8'));
}

module.exports = {

    readUsers: function () {
        return read(usersFolder);
    },

    writeUser: function (user) {
        let credentials = [];
        if (fs.existsSync(usersFolder)) {
            credentials = read(usersFolder);
        }
        credentials.push(user);
        write(credentials, usersFolder);
    },

    writeTask: function (task) {
        write(task, tasksFolder + task.id)
    },

    readTask: function (path) {
        return read(tasksFolder + path);
    },

    readAllTasks: function (content) {
        let tasks = [];
        fs.readdirSync(tasksFolder).forEach(file => {
            let task = this.readTask(file);
            if (task.content.includes(content))
                tasks.push(task);
        });
        return tasks;
    },

    delete: function (id) {
        try {
            fs.unlinkSync(tasksFolder + id);
        } catch (error) {
            console.log(error);
        }
    },
};
