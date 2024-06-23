import { Router } from 'express';
import userRouter from './user-routes.js';
import chatRoutes from './chat-routes.js';
const appRouter = Router();
appRouter.use('/user', userRouter); //domain/api/v1/user
appRouter.use('/chats', chatRoutes); //domain/api/v1/chat
export default appRouter;
//# sourceMappingURL=index.js.map