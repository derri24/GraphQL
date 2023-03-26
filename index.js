const express = require('express');

const jwt = require("jsonwebtoken");
const cookieParser = require('cookie-parser');

const {graphqlHTTP} = require('express-graphql');
const {buildSchema} = require('graphql');

let crypto = require('crypto')

let filesystem = require('./filesystem');


const PORT = 5050;
const PRIVATE_KEY = 'tr8j0e2w6q2';

var schema = buildSchema(`
    input UserInput {
        request: String
        name: String
        login: String
        password: String
    }
    
    input CredentialsInput {
        request: String
        login: String
        password: String
    }
    
    input CreatedDataInput {
        request: String
        task: TaskInput
    }
    
    input IdDataInput{
        request: String
        id: String
    }
    
    input SearchDataInput {
        request: String
        searchStr: String
    }
    
    input TaskInput {
        id: String
        content: String
        status: String
        date: String
        fileName: String
        fileContent: String
    }
    
    input UpdatedDataInput {
        request: String
        task: TaskInput
    }
    
    type Response {
        status: Int
        message: String
    }
    
    type Task {
        id: String
        content: String
        status: String
        date: String
        fileName: String
        fileContent: String
    }
    
    type TasksResponse {
        status: Int
        tasks: [Task]
    }
    
    type TaskResponse {
        status: Int
        task: Task
    }
   
    type Query {
        getAllTasks(input: SearchDataInput): TasksResponse
        getTask(input: IdDataInput): TaskResponse
    }
  
    type Mutation {
        registration(input: UserInput): Response
        authorization(input: CredentialsInput):Response
        
        create(input: CreatedDataInput): Response
        delete(input: IdDataInput): Response
        update(input: UpdatedDataInput): Response
    }
`);


const middleware = (req, res, next) => {
    try {
        if (req.url !== "/registration" && req.url !== "/authorization") {
            if ((req.url === "/graphql" && req.body.variables.input.request !== "registration"
                && req.body.variables.input.request !== "authorization") || req.url === "/index") {
                let token = req.cookies.authorization;
                jwt.verify(token, PRIVATE_KEY);
            }
        }
        next();
    } catch (err) {
        res.redirect(401, "/authorization");
    }
}


var root = {
    getAllTasks: ({input}) => {
        return getAllTasks(input);
    },

    getTask: ({input}) => {
        return getTask(input);
    },

    registration: ({input}) => {
        return registration(input);
    },

    authorization: (input, context) => {
        return authorization(input.input, context.res);
    },

    create: ({input}) => {
        return create(input)
    },

    delete: ({input}) => {
        return deleteTask(input)
    },

    update: ({input}) => {
        return update(input);
    }

};

function registration(user) {
    let response = {};
    if (user.name === "" || user.login === "" || user.password === "") {
        response.status = 403;
        response.message = "You should fill all fields!";
        return response;
    }
    if (user.password.length < 8) {
        response.status = 403;
        response.message = "Password should has length more than 7!";
        return response;
    }
    if (filesystem.readUsers().some(x => x.login === user.login)) {
        response.status = 403;
        response.message = "This login already exist!";
        return response;
    } else {
        response.status = 200;
        response.message = "Success!";

        let password = user.password;
        user.password = crypto.createHash('sha256').update(password).digest('hex');
        filesystem.writeUser(user);
    }
    return response;
}

function authorization(credentials, res) {
    let response = {};
    credentials.password = crypto.createHash('sha256').update(credentials.password).digest('hex');
    let users = filesystem.readUsers();

    if (users.some(x => x.login === credentials.login) && users.some(x => x.password === credentials.password)) {
        response.status = 200;

        let token = jwt.sign({
            name: credentials.name,
            login: credentials.login,
            creationTime: Date.now() + 1000 * 60 * 60 * 12
        }, PRIVATE_KEY);

        res.cookie('authorization', token, {
            expires: new Date(Date.now() + 1000 * 60 * 60 * 12),
            httpOnly: true
        });
    } else {
        response.status = 400;
        response.message = "Incorrect login or password!";
    }
    return response;
}

function getAllTasks(obj) {
    return {
        status: 200,
        tasks: filesystem.readAllTasks(obj.searchStr),
    };
}

function getTask(obj) {
    return {
        status: 200,
        task: filesystem.readTask(obj.id),
    };
}

function create(obj) {
    filesystem.writeTask(obj.task);
    return {status: 200};
}

function deleteTask(obj) {
    filesystem.delete(obj.id);
    return {status: 200};
}

function update(obj) {
    let task = obj.task;
    let oldTask = filesystem.readTask(task.id);
    oldTask.content = task.content;
    oldTask.status = task.status;
    oldTask.date = task.date;

    filesystem.writeTask(oldTask);
    return {status: 200};
}

let app = express();
app.use(express.json());
app.use(cookieParser());
app.use(middleware);


app.get("/registration", (req, res) => {
    res.sendFile(__dirname + "/views/registration.html");
})

app.get("/authorization", (req, res) => {
    res.sendFile(__dirname + "/views/authorization.html")
})

app.get("/index", (req, res) => {
    res.sendFile(__dirname + "/views/index.html");
})
app.use('/graphql', (req, res) => {
        return graphqlHTTP({
            schema,
            rootValue: root,
            graphiql: true,
            context: {req, res},
        })(req, res)
    }
);


app.listen(PORT);

