import app from "./app.js";
import connectToDatabase from "./db/connection.js";
//connections and listenres 
const PORT = process.env.PORT || 5003;
connectToDatabase().then(() => {
    app.listen(5003, () => console.log("Server is open and connected to DB"));
}).catch((err) => console.log(err));
//# sourceMappingURL=index.js.map